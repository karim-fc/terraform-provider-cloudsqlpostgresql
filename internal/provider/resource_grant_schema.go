package provider

import (
	"context"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &schemaGrantResource{}
	_ resource.ResourceWithConfigure = &schemaGrantResource{}
)

type schemaGrantResource struct {
	config *Config
}

type schemaGrantResourceModel struct {
	Connection types.String           `tfsdk:"connection_config"`
	Privileges []schemaPrivilegeModel `tfsdk:"privileges"`
	Schema     types.String           `tfsdk:"schema"`
	Role       types.String           `tfsdk:"role"`
}

type schemaPrivilegeModel struct {
	Privilege       types.String `tfsdk:"privilege"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
}

func newSchemaGrantResource() resource.Resource {
	return &schemaGrantResource{}
}

func (r *schemaGrantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant_schema"
}

func (r *schemaGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The `cloudsqlpostgresql_grant_schema` resource creates and manages privileges given to a user or role on a schema",
		MarkdownDescription: "The `cloudsqlpostgresql_grant_schema` resource creates and manages privileges given to a user or role on a schema",
		Attributes: map[string]schema.Attribute{
			"connection_config": schema.StringAttribute{
				Description:         "The key of the connection defined in the provider",
				MarkdownDescription: "The key of the connection defined in the provider",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role": schema.StringAttribute{
				Description:         "The name of the role to grant privileges on the schema. Can be username or role.",
				MarkdownDescription: "The name of the role to grant privileges on the schema. Can be username or role.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"schema": schema.StringAttribute{
				Description:         "The schema on which the privileges will be granted for this role.",
				MarkdownDescription: "The schema on which the privileges will be granted for this role.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_\-]*$`),
						"`schema` must be a correct name of a schema"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"privileges": schema.SetNestedAttribute{
				Description:         "A list of privileges to grant on the schema for this role.",
				MarkdownDescription: "A list of privileges to grant on the schema for this role.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"privilege": schema.StringAttribute{
							Description:         "The privilege to grant. Can only be one of 'CREATE', 'USAGE' or 'ALL'",
							MarkdownDescription: "The privilege to grant. Can only be one of 'CREATE', 'USAGE' or 'ALL'",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^CREATE|USAGE|ALL$`),
									"`privileges` can only be one of ('CREATE', 'USAGE' or 'ALL')"),
							},
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

func (r *schemaGrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan schemaGrantResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[plan.Connection.ValueString()]

	schema := plan.Schema.ValueString()
	database := connectionConfig.Database.ValueString()
	role := plan.Role.ValueString()

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

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error granting schema permissions",
			"Unable connect to database '"+database+"' to grant permissions of '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error granting schema permissions",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	if len(privilegesGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON SCHEMA %s TO \"%s\" WITH GRANT OPTION", strings.Join(privilegesGrant, ", "), schema, role)
		_, err := tx.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting schema permissions",
				"Unable to grant permissions to '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
			)
			return
		}
	}

	if len(privilegesNoGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON SCHEMA %s TO \"%s\"", strings.Join(privilegesNoGrant, ", "), schema, role)
		_, err := tx.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting schema permissions",
				"Unable to grant permissions to '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
			)
			return
		}
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error granting schema permissions",
			"Unable to commit, unexpected error: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *schemaGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state schemaGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[state.Connection.ValueString()]

	schema := state.Schema.ValueString()
	database := connectionConfig.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading database grant",
			"Unable connect to database '"+database+"' to read permissions of '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error(),
		)
		return
	}

	rows, err := db.QueryContext(ctx, "SELECT privilege_type, is_grantable FROM (SELECT (aclexplode(nspacl)).* FROM pg_namespace WHERE nspname = $1) as n WHERE n.grantee = $2::regrole;", schema, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading schema grant",
			"Unable to read privileges for '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error(),
		)
		return
	}

	var privileges []schemaPrivilegeModel
	for rows.Next() {
		var privilege string
		var isGrantable bool
		err = rows.Scan(&privilege, &isGrantable)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading schema grant",
				"Unable to read privileges for '"+role+"' on schema "+schema+", unexpected error: "+err.Error(),
			)
			return
		}
		privileges = append(privileges, schemaPrivilegeModel{
			Privilege:       types.StringValue(privilege),
			WithGrantOption: types.BoolValue(isGrantable),
		})
	}

	state.Privileges = privileges
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *schemaGrantResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// No updates possible, needs to recreate
}

func (r *schemaGrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state schemaGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[state.Connection.ValueString()]

	schema := state.Schema.ValueString()
	database := connectionConfig.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking schema permissions",
			"Unable connect to database '"+database+"' to revoke permissions of '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	var privileges []string
	for _, priv := range state.Privileges {
		privileges = append(privileges, priv.Privilege.ValueString())
	}

	sqlStatement := fmt.Sprintf("REVOKE %s ON SCHEMA %s FROM %s", strings.Join(privileges, ", "), schema, role)

	_, err = tx.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking schema permissions",
			"Unable to revoke permissions of '"+role+"' on schema "+schema+", unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
		)
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error revoking schema permissions",
			"Unable to commit, unexpected error: "+err.Error(),
		)
		return
	}
}

func (r *schemaGrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
