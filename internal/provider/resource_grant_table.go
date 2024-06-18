package provider

import (
	"context"
	"fmt"
	"reflect"
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
	Connection types.String          `tfsdk:"connection_config"`
	Privileges []tablePrivilegeModel `tfsdk:"privileges"`
	Schema     types.String          `tfsdk:"schema"`
	Table      types.String          `tfsdk:"table"`
	Role       types.String          `tfsdk:"role"`
}

type tablePrivilegeModel struct {
	Privilege       types.String `tfsdk:"privilege"`
	WithGrantOption types.Bool   `tfsdk:"with_grant_option"`
}

func (t *tableGrantResourceModel) isAllPrivilegesWithGrantOption() (bool, bool) {
	if len(t.Privileges) != 1 {
		return false, false
	}
	return t.Privileges[0].Privilege.ValueString() == "ALL", t.Privileges[0].WithGrantOption.ValueBool()
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
			"connection_config": schema.StringAttribute{
				Description:         "The key of the connection defined in the provider",
				MarkdownDescription: "The key of the connection defined in the provider",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role": schema.StringAttribute{
				Description:         "The name of the role to grant privileges on the table. Can be username or role.",
				MarkdownDescription: "The name of the role to grant privileges on the table. Can be username or role.",
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
			"table": schema.StringAttribute{ // TODO -  make table property safe, because otherwise someone can put like "table1, table2" and the grant will work
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

	connectionConfig := r.config.connections[plan.Connection.ValueString()]

	table := plan.Table.ValueString()
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
			"Error granting table permissions",
			"Unable connect to database '"+database+"' to grant permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error granting table permissions",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	tablePlaceholder := "TABLE " + schema + "." + table
	if table == "*" {
		tablePlaceholder = "ALL TABLES IN SCHEMA " + schema
	}

	if len(privilegesGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON %s TO \"%s\" WITH GRANT OPTION", strings.Join(privilegesGrant, ", "), tablePlaceholder, role)
		_, err := tx.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting table permissions",
				"Unable to grant permissions, unexpected error: "+err.Error(),
			)
			return
		}
	}

	if len(privilegesNoGrant) > 0 {
		sqlStatement := fmt.Sprintf("GRANT %s ON %s TO \"%s\"", strings.Join(privilegesNoGrant, ", "), tablePlaceholder, role)
		_, err := tx.ExecContext(ctx, sqlStatement)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error granting table permissions",
				"Unable to grant permissions, unexpected error: "+err.Error(),
			)
			return
		}
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error granting table permissions",
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

func (r *tableGrantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tableGrantResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[state.Connection.ValueString()]

	table := state.Table.ValueString()
	isAllTables := table == "*"
	schema := state.Schema.ValueString()
	database := connectionConfig.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading table grant",
			"Unable connect to database '"+database+"' to grant permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	sqlStatement := `select acls.relname, acls.privilege_type, acls.is_grantable  
	from (
		select relname, (aclexplode(relacl)).* from pg_catalog.pg_class as c
		where relnamespace = $1::regnamespace
	) as acls
	WHERE acls.grantee = $2::regrole`
	rows, err := db.QueryContext(ctx, sqlStatement, schema, role)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading table grant",
			"Unable to read privileges for '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	privileges := make(map[string][]tablePrivilegeModel)
	for rows.Next() {
		var relname string
		var privilege string
		var isGrantable bool
		err = rows.Scan(&relname, &privilege, &isGrantable)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error reading table grant",
				"Unable to read privileges for '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
			)
			return
		}

		if !isAllTables && relname != table {
			continue // skip
		}

		privileges[relname] = append(privileges[relname], tablePrivilegeModel{
			Privilege:       types.StringValue(privilege),
			WithGrantOption: types.BoolValue(isGrantable),
		})
	}

	for _, priv := range privileges {
		allPriv, grantOption := state.isAllPrivilegesWithGrantOption()

		if allPriv {
			eq := true
			for _, p := range priv {
				if p.WithGrantOption.ValueBool() != grantOption {
					state.Privileges = priv
					eq = false
					break
				}
			}
			if !eq {
				break
			}

			if containsAllPrivileges(priv) {
				allPrivileges := []tablePrivilegeModel{}
				allPrivileges = append(allPrivileges, tablePrivilegeModel{
					Privilege:       types.StringValue("ALL"),
					WithGrantOption: priv[0].WithGrantOption,
				})
				state.Privileges = allPrivileges
				continue
			}
		}

		state.Privileges = priv
		if !reflect.DeepEqual(state.Privileges, priv) { // Be sure to show the changes of the one table that has different privileges
			break
		}
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

	connectionConfig := r.config.connections[state.Connection.ValueString()]

	table := state.Table.ValueString()
	schema := state.Schema.ValueString()
	database := connectionConfig.Database.ValueString()
	role := state.Role.ValueString()

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking table permissions",
			"Unable connect to database '"+database+"' to revoke permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking table permissions",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	var privileges []string
	for _, priv := range state.Privileges {
		privileges = append(privileges, priv.Privilege.ValueString())
	}

	tablePlaceholder := "TABLE " + schema + "." + table
	if table == "*" {
		tablePlaceholder = "ALL TABLES IN SCHEMA " + schema
	}

	sqlStatement := fmt.Sprintf("REVOKE %s ON %s FROM \"%s\"", strings.Join(privileges, ", "), tablePlaceholder, role)

	_, err = tx.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error revoking table permissions",
			"Unable to revoke permissions of '"+role+"' on table '"+schema+"."+table+"', unexpected error: "+err.Error(),
		)
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error revoking table permissions",
			"Unable to commit, unexpected error: "+err.Error(),
		)
		return
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
