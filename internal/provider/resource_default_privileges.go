package provider

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &defaultPriviligesResource{}
	_ resource.ResourceWithConfigure = &defaultPriviligesResource{}
)

type defaultPriviligesResource struct {
	config *Config
}

type defaultPriviligesResourceModel struct {
	Connection types.String                      `tfsdk:"connection_config"`
	Owner      types.String                      `tfsdk:"owner"`
	Role       types.String                      `tfsdk:"role"`
	Schema     types.String                      `tfsdk:"schema"`
	ObjectType types.String                      `tfsdk:"object_type"`
	Privileges []defaultPrivilegesPrivilegeModel `tfsdk:"privileges"`
}

type defaultPrivilegesPrivilegeModel struct {
	Privilege       types.String `tfsdk:"privilege"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
}

func newDefaultPrivilegesResource() resource.Resource {
	return &defaultPriviligesResource{}
}

func (r *defaultPriviligesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_default_privileges"
}

func (r *defaultPriviligesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The `cloudsqlpostgresql_default_privileges` resource allows to set the privileges that will be applied to objects created in the future. (It does not affect privileges assigned to already-existing objects.).",
		MarkdownDescription: "The `cloudsqlpostgresql_default_privileges` resource allows to set the privileges that will be applied to objects created in the future. (It does not affect privileges assigned to already-existing objects.).",
		Attributes: map[string]schema.Attribute{
			"connection_config": schema.StringAttribute{
				Description:         "The key of the connection defined in the provider",
				MarkdownDescription: "The key of the connection defined in the provider",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"owner": schema.StringAttribute{
				Description:         "The target role",
				MarkdownDescription: "The target role",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role": schema.StringAttribute{
				Description:         "The role",
				MarkdownDescription: "The role",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"schema": schema.StringAttribute{
				Description:         "The schema",
				MarkdownDescription: "The schema",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"object_type": schema.StringAttribute{
				Description:         "The object type, can be `TABLES`, `SEQUENCES`, `FUNCTIONS`, `ROUTINES`, `TYPES` or `SCHEMAS`. Defaults to `TABLES`.",
				MarkdownDescription: "The object type, can be `TABLES`, `SEQUENCES`, `FUNCTIONS`, `ROUTINES`, `TYPES` or `SCHEMAS`. Defaults to `TABLES`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("TABLES"),
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^TABLES|SEQUENCES|FUNCTIONS|ROUTINES|TYPES|SCHEMAS$`),
						"`object_type` can only be one of `TABLES`, `SEQUENCES`, `FUNCTIONS`, `ROUTINES`, `TYPES` or `SCHEMAS`"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"privileges": schema.SetNestedAttribute{
				Description:         "A list of privileges",
				MarkdownDescription: "A list of privileges",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"privilege": schema.StringAttribute{
							Description:         "The privilege to grant",
							MarkdownDescription: "The privilege to grant",
							Required:            true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"with_grant_option": schema.BoolAttribute{
							Description:         "Whether the role can grant the same privileges to others.",
							MarkdownDescription: "Whether the role can grant the same privileges to others.",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.RequiresReplace(),
							},
						},
					},
				},
				Required: true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *defaultPriviligesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan defaultPriviligesResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[plan.Connection.ValueString()]

	database := connectionConfig.Database.ValueString()
	owner := plan.Owner.ValueString()
	role := plan.Role.ValueString()
	objectType := plan.ObjectType.ValueString()

	var privilegesNoGrant []string
	var privilegesGrant []string
	for _, priv := range plan.Privileges {
		privilege := priv.Privilege.ValueString()
		withGrantOption := priv.WithGrantOption.ValueBool()
		if withGrantOption {
			privilegesGrant = append(privilegesGrant, privilege)
			continue
		}
		privilegesNoGrant = append(privilegesNoGrant, privilege)
	}

	inSchema := ""
	if !plan.Schema.IsNull() && plan.Schema.ValueString() != "" {
		inSchema = "IN SCHEMA " + plan.Schema.ValueString()
	}

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
			"Unable to connect to the database, unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error setting the default privileges",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	err = r.revokeAll(ctx, tx, owner, inSchema, objectType, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error setting the default privileges",
			"Unexpected error: "+err.Error(),
		)
		return
	}

	if len(privilegesGrant) > 0 {
		sqlStatement := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE \"%s\" %s GRANT %s ON %s TO \"%s\" WITH GRANT OPTION;", owner, inSchema, strings.Join(privilegesGrant, ", "), objectType, role)
		_, err := tx.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error setting the default privileges",
				"Unable to set the default privileges to '"+role+"' on database '"+database+"', unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
			)
			return
		}
	}

	if len(privilegesNoGrant) > 0 {
		sqlStatement := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE \"%s\" %s GRANT %s ON %s TO \"%s\";", owner, inSchema, strings.Join(privilegesNoGrant, ", "), objectType, role)
		_, err := tx.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error setting the default privileges",
				"Unable to set the default privileges to '"+role+"' on database '"+database+"', unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
			)
			return
		}
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error setting the default privileges",
			"Unable to commit the default privileges to '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

func (r *defaultPriviligesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state defaultPriviligesResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	owner := state.Owner.ValueString()
	role := state.Role.ValueString()

	var schema string = "-"
	if !state.Schema.IsNull() {
		schema = state.Schema.ValueString()
	}

	connectionConfig := r.config.connections[state.Connection.ValueString()]
	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading default privileges",
			"Unable to connect to the database, unexpected error: "+err.Error(),
		)
		return
	}

	sqlStatement := `SELECT res.owner, res.schema, res.object_type, res.grantee::regrole as grantee, res.privilege_type, res.is_grantable FROM (
		SELECT 
			dacl.defaclrole::regrole AS owner, 
			dacl.defaclnamespace::regnamespace AS schema, 
			dacl.defaclobjtype AS object_type, 
			(aclexplode(dacl.defaclacl)).* AS default_permissions 
		FROM pg_catalog.pg_default_acl as dacl
		WHERE dacl.defaclrole = $1::regrole 
			AND dacl.defaclnamespace = $2::regnamespace
		) AS res 
		WHERE res.grantee = $3::regrole`

	rows, err := db.QueryContext(ctx, sqlStatement, owner, schema, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading default privileges",
			"Unable to read the default privileges, unexpected error: "+err.Error(),
		)
		return
	}
	defer rows.Close()

	var (
		ownerResult, schemaResult, objectTypeResult, grantee, privilege string
		grantOption                                                     bool
		privileges                                                      []defaultPrivilegesPrivilegeModel
	)

	values := []interface{}{
		&ownerResult,
		&schemaResult,
		&objectTypeResult,
		&grantee,
		&privilege,
		&grantOption,
	}

	for rows.Next() {
		err = rows.Scan(values...)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading default privileges",
				"Unable to read the default privileges, unexpected error: "+err.Error(),
			)
			return
		}
		privileges = append(privileges, defaultPrivilegesPrivilegeModel{
			Privilege:       types.StringValue(privilege),
			WithGrantOption: types.BoolValue(grantOption),
		})
	}

	state.Owner = types.StringValue(ownerResult)
	state.Role = types.StringValue(grantee)
	state.Privileges = privileges
	if schemaResult == "-" {
		state.Schema = types.StringNull()
	} else {
		state.Schema = types.StringValue(schemaResult)
	}

	var objectType string
	switch objectTypeResult {
	case "r":
		objectType = "TABLES"
	case "S":
		objectType = "SEQUENCES"
	case "f":
		objectType = "FUNCTIONS"
	case "T":
		objectType = "TYPES"
	case "n":
		objectType = "SCHEMAS"
	}

	state.ObjectType = types.StringValue(objectType)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *defaultPriviligesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *defaultPriviligesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state defaultPriviligesResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[state.Connection.ValueString()]
	database := connectionConfig.Database.ValueString()
	owner := state.Owner.ValueString()
	role := state.Role.ValueString()
	objectType := state.ObjectType.ValueString()

	inSchema := ""
	if !state.Schema.IsNull() && state.Schema.ValueString() != "" {
		inSchema = "IN SCHEMA " + state.Schema.ValueString()
	}

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error removing default privileges",
			"Unable to connect to the database, unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error removing default privileges",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	err = r.revokeAll(ctx, tx, owner, inSchema, objectType, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error removing default privileges",
			"Unexpected error: "+err.Error(),
		)
		return
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error removing the default privileges",
			"Unable to commit the default privileges from '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
		)
		return
	}
}

func (r *defaultPriviligesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*Config)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *Config, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.config = config
}

func (r *defaultPriviligesResource) revokeAll(ctx context.Context, tx *sql.Tx, owner string, inSchema string, objectType string, role string) error {
	sqlStatement := fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE \"%s\" %s REVOKE ALL ON %s FROM \"%s\"", owner, inSchema, objectType, role)
	tflog.Debug(ctx, "The SQL statement: "+sqlStatement)

	_, err := tx.ExecContext(ctx, sqlStatement)
	return err
}
