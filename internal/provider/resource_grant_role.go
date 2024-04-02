package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &roleGrantResource{}
	_ resource.ResourceWithConfigure = &roleGrantResource{}
)

type roleGrantResource struct {
	config *Config
}

type roleGrantResourceModel struct {
	GroupRole types.String `tfsdk:"group_role"`
	Role      types.String `tfsdk:"role"`
	// InheritOption types.Bool   `tfsdk:"inherit_option"`
	// SetOption     types.Bool   `tfsdk:"set_option"`
	AdminOption types.Bool `tfsdk:"admin_option"`
}

func newRoleGrantResource() resource.Resource {
	return &roleGrantResource{}
}

func (r *roleGrantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant_role"
}

func (r *roleGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The `cloudsqlpostgresql_grant_role` resource creates and manages role membership.",
		MarkdownDescription: "The `cloudsqlpostgresql_grant_role` resource creates and manages role membership.",
		Attributes: map[string]schema.Attribute{
			"group_role": schema.StringAttribute{
				Description:         "The `group_role` that will get the `role` as member",
				MarkdownDescription: "The `group_role` that will get the `role` as member",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role": schema.StringAttribute{
				Description:         "The `role` that will be a member of the `group_role`",
				MarkdownDescription: "The `role` that will be a member of the `group_role`",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			// "inherit_option": schema.BoolAttribute{
			// 	Description:         "Enable inherit option",
			// 	MarkdownDescription: "Enable inherit option",
			// 	Optional:            true,
			// 	Computed:            true,
			// 	Default:             booldefault.StaticBool(false),
			// },

			// "set_option": schema.BoolAttribute{
			// 	Description:         "Enable set option",
			// 	MarkdownDescription: "Enable set option",
			// 	Optional:            true,
			// 	Computed:            true,
			// 	Default:             booldefault.StaticBool(true),
			// },
			"admin_option": schema.BoolAttribute{
				Description:         "Enable admin option",
				MarkdownDescription: "Enable admin option",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
		},
	}
}

func (r *roleGrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleGrantResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	db, err := r.config.connectToPostgresqlNoDb()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
			"Unable to connect to the database, unexpected error: "+err.Error(),
		)
		return
	}

	options := r.generateOptions(&plan)
	sqlStatement := fmt.Sprintf("GRANT %s TO %s", plan.GroupRole.ValueString(), plan.Role.ValueString())
	if len(options) > 0 {
		sqlStatement = sqlStatement + " WITH " + strings.Join(options, ", ")
	}

	_, err = db.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating grant role on group role",
			"Unable to execute sql statement, unexpected error: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *roleGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleGrantResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.readGrantRole(ctx, &state)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading grant role",
			"Unable to connect to database, unexpected error: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *roleGrantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleGrantResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state roleGrantResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	db, err := r.config.connectToPostgresqlNoDb()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating grant role",
			"Unable to connect to the database, unexpected error: "+err.Error(),
		)
		return
	}

	var sqlStatement string
	if !state.AdminOption.IsNull() && state.AdminOption.ValueBool() && !plan.AdminOption.ValueBool() { // if state's admin_option is true and the plan's admin_option is false
		sqlStatement = fmt.Sprintf("REVOKE ADMIN OPTION FOR %s FROM %s", plan.GroupRole.ValueString(), plan.Role.ValueString())
	} else {
		options := r.generateOptions(&plan)
		sqlStatement = fmt.Sprintf("GRANT %s TO %s", plan.GroupRole.ValueString(), plan.Role.ValueString())
		if len(options) > 0 {
			sqlStatement = sqlStatement + " WITH " + strings.Join(options, ", ")
		}
	}
	_, err = db.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating grant role on group role",
			"Unable to execute sql statement, unexpected error: "+err.Error(),
		)
		return
	}

	err = r.readGrantRole(ctx, &plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating grant role on group role",
			"Unable to execute sql statement, unexpected error: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *roleGrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleGrantResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	db, err := r.config.connectToPostgresqlNoDb()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting grant role",
			"Unable connect to database, unexpected error: "+err.Error(),
		)
		return
	}

	_, err = db.ExecContext(ctx, "REVOKE "+state.GroupRole.ValueString()+" FROM "+state.Role.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting role",
			"Unable to revoke the role, unexpected error: "+err.Error(),
		)
		return
	}
}

func (r *roleGrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *roleGrantResource) readGrantRole(ctx context.Context, grant *roleGrantResourceModel) error {
	db, err := r.config.connectToPostgresqlNoDb()
	if err != nil {
		return err
	}

	var (
		groupRole, role string
		adminOption     bool
	)

	values := []interface{}{
		&groupRole,
		&role,
		&adminOption,
	}

	sqlStatement := `select r.rolname as role, m.rolname as member, am.admin_option 
	from pg_catalog.pg_auth_members as am
	left join pg_catalog.pg_roles as r on r.oid = am.roleid
	left join pg_catalog.pg_roles as m on m.oid = am.member
	where r.rolname = $1 and m.rolname = $2;`

	err = db.QueryRowContext(ctx, sqlStatement, grant.GroupRole.ValueString(), grant.Role.ValueString()).Scan(values...)
	if err != nil {
		return err
	}

	grant.GroupRole = types.StringValue(groupRole)
	grant.Role = types.StringValue(role)
	grant.AdminOption = types.BoolValue(adminOption)
	return nil
}

func (r *roleGrantResource) generateOptions(grant *roleGrantResourceModel) []string {
	var options []string
	if !grant.AdminOption.IsNull() && grant.AdminOption.ValueBool() {
		options = append(options, "ADMIN OPTION")
	}
	// if !grant.InheritOption.IsNull() && grant.InheritOption.ValueBool() {
	// 	options = append(options, "INHERIT TRUE")
	// } else {
	// 	options = append(options, "INHERIT FALSE")
	// }

	// if !grant.SetOption.IsNull() && grant.SetOption.ValueBool() {
	// 	options = append(options, "SET TRUE")
	// } else {
	// 	options = append(options, "SET FALSE")
	// }
	return options
}
