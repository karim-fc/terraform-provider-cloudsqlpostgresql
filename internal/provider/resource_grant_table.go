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
	_ resource.Resource              = &tableGrantResource{}
	_ resource.ResourceWithConfigure = &tableGrantResource{}
)

type tableGrantResource struct {
	config *Config
}

type tableGrantResourceModel struct {
	Privileges []tablePrivilegeModel `tfsdk:"privileges"`
	Database   types.String          `tfsdk:"database"`
	Schema     types.String          `tfsdk:"schema"`
	Table      types.String          `tfsdk:"table"`
	Role       types.String          `tfsdk:"role"`
}

func (t *tableGrantResourceModel) hasAllPrivileges() bool {
	for _, priv := range t.Privileges {
		if priv.Privilege.ValueString() == "ALL" {
			return true
		}
	}
	return false
}

type tablePrivilegeModel struct {
	Privilege       types.String `tfsdk:"privilege"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
}

func newTableGrantResource() resource.Resource {
	return &tableGrantResource{}
}

func (r *tableGrantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant_table"
}

func (r *tableGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The `cloudsqlpostgresql_grant_table` resource creates and manages privileges given to a user or role on a table",
		MarkdownDescription: "The `cloudsqlpostgresql_grant_table` resource creates and manages privileges given to a user or role on a table",
		Attributes: map[string]schema.Attribute{
			"role": schema.StringAttribute{
				Description:         "The name of the role to grant privileges on the table. Can be username or role.",
				MarkdownDescription: "The name of the role to grant privileges on the table. Can be username or role.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"database": schema.StringAttribute{
				Description:         "The database where the table resides.",
				MarkdownDescription: "The database where the table resides.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"schema": schema.StringAttribute{
				Description:         "The schema where the table resides.",
				MarkdownDescription: "The schema where the table resides.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"table": schema.StringAttribute{ // make table property safe, because otherwise someone can put like "table1, table2" and the grant will work
				Description:         "The table on which the privileges will be granted for this role.",
				MarkdownDescription: "The table on which the privileges will be granted for this role.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"privileges": schema.SetNestedAttribute{
				Description:         "A list of privileges to grant on the table for this role.",
				MarkdownDescription: "A list of privileges to grant on the table for this role.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"privilege": schema.StringAttribute{
							Description:         "The privilege to grant. Can only be one of 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER' or 'ALL'",
							MarkdownDescription: "The privilege to grant. Can only be one of `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER` or `ALL`",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^SELECT|INSERT|UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER|ALL$`),
									"`privileges` can only be one of ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER' or 'ALL')"),
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

func (r *tableGrantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tableGrantResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	table := plan.Table.ValueString()
	schema := plan.Schema.ValueString()
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
			"Error granting table permissions",
			"Unable connect to database '"+database+"' to grant permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	tablePlaceholder := "TABLE " + schema + "." + table
	// if table == "*" { // will not support granting on all tables in a schema, because it will be difficult to see the difference otherwise later
	// 	tablePlaceholder = "ALL TABLES IN SCHEMA " + schema
	// }

	if len(privilegesGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON %s TO %s WITH GRANT OPTION", strings.Join(privilegesGrant, ", "), tablePlaceholder, role)
		_, err := db.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting schema permissions",
				"Unable to grant permissions to '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error(),
			)
			return
		}
	}

	if len(privilegesNoGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON %s TO %s", strings.Join(privilegesNoGrant, ", "), tablePlaceholder, role)
		_, err := db.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting database permissions",
				"Unable to grant permissions to '"+role+"' on schema '"+schema+"', unexpected error: "+err.Error(),
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

func (r *tableGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

	var state tableGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	table := state.Table.ValueString()
	schema := state.Schema.ValueString()
	database := state.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresqlDb(database)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading table grant",
			"Unable connect to database '"+database+"' to grant permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	oid, err := fetchOidForRole(ctx, db, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading table grant",
			"Unable to fetch oid for the role '"+role+"', unexpected error: "+err.Error(),
		)
		return
	}

	rows, err := db.QueryContext(ctx, "SELECT privilege_type, is_grantable FROM (select (aclexplode(c.relacl)).* from pg_catalog.pg_class as c left join pg_catalog.pg_namespace as n on n.oid = c.relnamespace where n.nspname = $1 and c.relname = $2 and c.relkind = 'r') as acl WHERE grantee = $3", schema, table, oid)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading table grant",
			"Unable to read privileges for '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	var privileges []tablePrivilegeModel
	for rows.Next() {
		var privilege string
		var isGrantable bool
		err = rows.Scan(&privilege, &isGrantable)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading table grant",
				"Unable to read privileges for '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
			)
			return
		}
		privileges = append(privileges, tablePrivilegeModel{
			Privilege:       types.StringValue(privilege),
			WithGrantOption: types.BoolValue(isGrantable),
		})
	}

	if state.hasAllPrivileges() && containsAllPrivileges(privileges) {
		allPrivileges := []tablePrivilegeModel{}
		allPrivileges = append(allPrivileges, tablePrivilegeModel{
			Privilege:       types.StringValue("ALL"),
			WithGrantOption: privileges[0].WithGrantOption,
		})
		state.Privileges = allPrivileges
	} else {
		state.Privileges = privileges
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *tableGrantResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// No updates possible, needs to recreate
}

func (r *tableGrantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tableGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	table := state.Table.ValueString()
	schema := state.Schema.ValueString()
	database := state.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresqlDb(database)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking table permissions",
			"Unable connect to database '"+database+"' to revoke permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	var privileges []string
	for _, priv := range state.Privileges {
		privileges = append(privileges, priv.Privilege.ValueString())
	}

	sqlStatement := fmt.Sprintf("REVOKE %s ON TABLE %s.%s FROM %s", strings.Join(privileges, ", "), schema, table, role)

	_, err = db.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking table permissions",
			"Unable to revoke permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
	}
}

func (r *tableGrantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func containsAllPrivileges(privileges []tablePrivilegeModel) bool {
	for _, priv := range getAllPrivilegesForGrantTable() {
		if !containsPrivilege(privileges, priv) {
			return false
		}
	}
	return true
}

func containsPrivilege(privileges []tablePrivilegeModel, privilege string) bool {
	for _, priv := range privileges {
		if priv.Privilege.ValueString() == privilege {
			return true
		}
	}
	return false
}

func getAllPrivilegesForGrantTable() []string {
	return []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
}
