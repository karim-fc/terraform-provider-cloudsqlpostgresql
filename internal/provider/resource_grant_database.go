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
	_ resource.Resource              = &databaseGrantResource{}
	_ resource.ResourceWithConfigure = &databaseGrantResource{}
)

type databaseGrantResource struct {
	config *Config
}

type databaseGrantResourceModel struct {
	Privileges []databasePrivilegeModel `tfsdk:"privileges"`
	Database   types.String             `tfsdk:"database"`
	Role       types.String             `tfsdk:"role"`
}

type databasePrivilegeModel struct {
	Privilege       types.String `tfsdk:"privilege"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
}

func newDatabaseGrantResource() resource.Resource {
	return &databaseGrantResource{}
}

func (r *databaseGrantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant_database"
}

func (r *databaseGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The `cloudsqlpostgresql_grant_database` resource creates and manages privileges given to a user or role on a database",
		MarkdownDescription: "The cloudsqlpostgresql_grant_database resource creates and manages privileges given to a user or role on a database",
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description:         "The name of the role to grant privileges on the database. Can be username or role.",
				MarkdownDescription: "The name of the role to grant privileges on the database. Can be username or role.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"database": schema.StringAttribute{
				Description:         "The database on which the privileges will be granted for this role.",
				MarkdownDescription: "The database on which the privileges will be granted for this role.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_\-]*$`),
						"`database` must be a correct name of a database"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"privileges": schema.SetNestedAttribute{
				Description:         "A list of privileges to grant on the database for this role.",
				MarkdownDescription: "A list of privileges to grant on the database for this role.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"privilege": schema.StringAttribute{
							Description:         "The privilege to grant. Can only be one of 'CREATE', 'CONNECT', 'TEMP', 'TEMPORARY' or 'ALL'",
							MarkdownDescription: "The privilege to grant. Can only be one of `CREATE`, `CONNECT`, `TEMP`, `TEMPORARY` or `ALL`",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^CREATE|CONNECT|TEMPORARY|TEMP|ALL$`),
									"`privileges` can only be one of 'CREATE', 'CONNECT', 'TEMP', 'TEMPORARY' or 'ALL'"),
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

func (r *databaseGrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan databaseGrantResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	database := plan.Database.ValueString()
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

	db, err := r.config.connectToPostgresqlDb(database)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error granting database permissions",
			"Unable connect to database to grant permissions to '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
		)
		return
	}

	if len(privilegesGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON DATABASE %s TO %s WITH GRANT OPTION", strings.Join(privilegesGrant, ", "), database, role)
		_, err := db.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting database permissions",
				"Unable to grant permissions to '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
			)
			return
		}
	}

	if len(privilegesNoGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON DATABASE %s TO %s", strings.Join(privilegesNoGrant, ", "), database, role)
		_, err := db.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting database permissions",
				"Unable to grant permissions to '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
			)
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *databaseGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state databaseGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	database := state.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresqlDb(database)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading database grant",
			"Unable connect to database to read permissions of "+role+" on database '"+database+"', unexpected error: "+err.Error(),
		)
		return
	}

	oid, err := fetchOidForRole(ctx, db, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading database grant",
			"Unable to fetch oid for the role "+role+", unexpected error: "+err.Error(),
		)
		return
	}

	rows, err := db.QueryContext(ctx, "SELECT privilege_type, is_grantable FROM (SELECT (aclexplode(datacl)).* FROM pg_database WHERE datname = $1) as d WHERE d.grantee = $2", database, oid)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading database grant",
			"Unable to read privileges for '"+role+"' on databse '"+database+"', unexpected error: "+err.Error(),
		)
		return
	}

	var privileges []databasePrivilegeModel
	for rows.Next() {
		var privilege string
		var isGrantable bool
		err = rows.Scan(&privilege, &isGrantable)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading database grant",
				"Unable to read privileges for '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
			)
			return
		}
		privileges = append(privileges, databasePrivilegeModel{
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

func (r *databaseGrantResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// No updates possible, needs to recreate
}

func (r *databaseGrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state databaseGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	database := state.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresqlDb(database)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking permissions",
			"Unable connect to database to revoke permissions of '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
		)
		return
	}

	var privileges []string
	for _, priv := range state.Privileges {
		privileges = append(privileges, priv.Privilege.ValueString())
	}

	sqlStatement := fmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s", strings.Join(privileges, ", "), database, role)

	_, err = db.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking permissions",
			"Unable to revoke permissions of '"+role+"' on database '"+database+"', unexpected error: "+err.Error(),
		)
	}
}

func (r *databaseGrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
