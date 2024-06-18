package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &roleResource{}
	_ resource.ResourceWithConfigure = &roleResource{}
)

type roleResource struct {
	config *Config
}

type roleResourceModel struct {
	Connection           types.String         `tfsdk:"connection_config"`
	Name                 types.String         `tfsdk:"name"`
	Password             types.String         `tfsdk:"password"`
	IsUser               types.Bool           `tfsdk:"is_user"`
	HasCreatedbOption    types.Bool           `tfsdk:"has_createdb_option"`
	HasCreateroleOption  types.Bool           `tfsdk:"has_createrole_option"`
	HasInheritOption     types.Bool           `tfsdk:"has_inherit_option"`
	HasReplicationOption types.Bool           `tfsdk:"has_replication_option"`
	HasBypassrlsOption   types.Bool           `tfsdk:"has_bypassrls_option"`
	ConnectionLimit      types.Int64          `tfsdk:"connection_limit"`
	IsValidUntil         CustomTimestampValue `tfsdk:"is_valid_until"`
}

func newRoleResource() resource.Resource {
	return &roleResource{}
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The `cloudsqlpostgresql_role` resource creates and manages a role. The superuser option is not supported on Cloud SQL.",
		MarkdownDescription: "The `cloudsqlpostgresql_role` resource creates and manages a role. The superuser option is not supported on Cloud SQL.",
		Attributes: map[string]schema.Attribute{
			"connection_config": schema.StringAttribute{
				Description:         "The key of the connection defined in the provider",
				MarkdownDescription: "The key of the connection defined in the provider",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description:         "The name of the role",
				MarkdownDescription: "The name of the role",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Description:         "Sets the role's password",
				MarkdownDescription: "Sets the role's password",
				Optional:            true,
				Sensitive:           true,
			},
			"is_user": schema.BoolAttribute{
				Description:         "Is this role a user that can login",
				MarkdownDescription: "Is this role a user that can login",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"has_createdb_option": schema.BoolAttribute{
				Description:         "Whether or not this role has the CREATEDB option",
				MarkdownDescription: "Whether or not this role has the CREATEDB option",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"has_createrole_option": schema.BoolAttribute{
				Description:         "Whether the role has the CREATEROLE option",
				MarkdownDescription: "Whether the role has the CREATEROLE option",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"has_inherit_option": schema.BoolAttribute{
				Description:         "Whether the role has the INHERIT option",
				MarkdownDescription: "Whether the role has the INHERIT option",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"has_replication_option": schema.BoolAttribute{
				Description:         "Whether the role has the REPLICATION option",
				MarkdownDescription: "Whether the role has the REPLICATION option",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"has_bypassrls_option": schema.BoolAttribute{
				Description:         "Whether the role has the BYPASSRLS option",
				MarkdownDescription: "Whether the role has the BYPASSRLS option",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"connection_limit": schema.Int64Attribute{
				Description:         "Specifies how many concurrent connections the role can make. -1 (the default) means no limit",
				MarkdownDescription: "Specifies how many concurrent connections the role can make. -1 (the default) means no limit",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(-1),
			},
			"is_valid_until": schema.StringAttribute{
				Description:         "Sets a date and time after which the role's password is no longer valid",
				MarkdownDescription: "Sets a date and time after which the role's password is no longer valid",
				Optional:            true,
				CustomType:          CustomTimestampType{},
			},
		},
	}
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[plan.Connection.ValueString()]

	name := plan.Name.ValueString()
	options := r.generateOptions(&plan)

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
			"Unable to connect to the database to create the role "+name+", unexpected error: "+err.Error(),
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

	sqlStatement := "CREATE ROLE \"" + name + "\""
	if len(options) > 0 {
		sqlStatement = sqlStatement + " WITH " + strings.Join(options, " ")
	}
	_, err = tx.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
			"Unable to execute sql statement, unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
		)
		return
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
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

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.readRole(ctx, &state)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading role",
			"Unable to connect to database to read role '"+state.Name.ValueString()+"', unexpected error: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[plan.Connection.ValueString()]

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating role",
			"Unable to connect to the database to create the role '"+plan.Name.ValueString()+"', unexpected error: "+err.Error(),
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

	options := r.generateOptions(&plan)
	sqlStatement := "ALTER ROLE \"" + plan.Name.ValueString() + "\""
	if len(options) > 0 {
		sqlStatement = sqlStatement + " WITH " + strings.Join(options, " ")
	}
	_, err = tx.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating role",
			"Unable to execute sql statement, unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
		)
		return
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error updating role",
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

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	connectionConfig := r.config.connections[state.Connection.ValueString()]

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting role",
			"Unable connect to database to delete role '"+state.Name.ValueString()+"', unexpected error: "+err.Error(),
		)
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error removing role",
			"Unable to create transaction to the database, unexpected error: "+err.Error(),
		)
		return
	}
	defer txRollback(ctx, tx)

	sqlStatement := "DROP ROLE \"" + state.Name.ValueString() + "\";"

	_, err = tx.ExecContext(ctx, sqlStatement)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting role",
			"Unable to drop the role '"+state.Name.ValueString()+"', unexpected error: "+err.Error()+"\nSQL Statement: "+sqlStatement,
		)
		return
	}

	if err = tx.Commit(); err != nil {
		resp.Diagnostics.AddError(
			"Error deleting role",
			"Unable to commit, unexpected error: "+err.Error(),
		)
		return
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *roleResource) readRole(ctx context.Context, role *roleResourceModel) error {
	connectionConfig := r.config.connections[role.Connection.ValueString()]

	db, err := r.config.connectToPostgresql(ctx, connectionConfig)
	if err != nil {
		return err
	}

	var (
		name, password, isValidUntil                               string
		isUser, hasCreatedbOption, hasCreateroleOption             bool
		hasInheritOption, hasReplicationOption, hasBypassrlsOption bool
		connectionLimit                                            int64
	)
	values := []interface{}{
		&name,
		&password,
		&isUser,
		&hasCreatedbOption,
		&hasCreateroleOption,
		&hasInheritOption,
		&hasReplicationOption,
		&hasBypassrlsOption,
		&connectionLimit,
		&isValidUntil,
	}

	sqlStatement := `select r.rolname, r.rolpassword, r.rolcanlogin, r.rolcreatedb, r.rolcreaterole, r.rolinherit, r.rolreplication, r.rolbypassrls, r.rolconnlimit, r.rolvaliduntil from pg_catalog.pg_roles as r where r.rolname = $1;`
	err = db.QueryRowContext(ctx, sqlStatement, role.Name.ValueString()).Scan(values...)
	if err != nil {
		return err
	}

	role.Name = types.StringValue(name)
	// password changes are neglected
	role.IsUser = types.BoolValue(isUser)
	role.HasCreatedbOption = types.BoolValue(hasCreatedbOption)
	role.HasCreateroleOption = types.BoolValue(hasCreateroleOption)
	role.HasInheritOption = types.BoolValue(hasInheritOption)
	role.HasReplicationOption = types.BoolValue(hasReplicationOption)
	role.HasBypassrlsOption = types.BoolValue(hasBypassrlsOption)
	role.ConnectionLimit = types.Int64Value(connectionLimit)

	if isValidUntil == "infinity" {
		role.IsValidUntil = NewCustomTimestampNull()
	} else {
		isValidUntilTime, _ := time.Parse(time.RFC3339, isValidUntil)
		utcLocation, _ := time.LoadLocation("UTC")
		role.IsValidUntil = NewCustomTimestampValue(isValidUntilTime.In(utcLocation).Format(time.DateTime))
	}
	return nil
}

func (r *roleResource) generateOptions(plan *roleResourceModel) []string {
	var options []string

	if !plan.Password.IsNull() && len(plan.Password.ValueString()) > 0 {
		options = append(options, "PASSWORD '"+plan.Password.ValueString()+"'")
	} else {
		options = append(options, "PASSWORD NULL")
	}

	if !plan.IsUser.IsNull() && plan.IsUser.ValueBool() {
		options = append(options, "LOGIN")
	} else {
		options = append(options, "NOLOGIN")
	}

	if !plan.HasBypassrlsOption.IsNull() && plan.HasBypassrlsOption.ValueBool() {
		options = append(options, "BYPASSRLS")
	} else {
		options = append(options, "NOBYPASSRLS")
	}

	if !plan.HasCreatedbOption.IsNull() && plan.HasCreatedbOption.ValueBool() {
		options = append(options, "CREATEDB")
	} else {
		options = append(options, "NOCREATEDB")
	}

	if !plan.HasCreateroleOption.IsNull() && plan.HasCreateroleOption.ValueBool() {
		options = append(options, "CREATEROLE")
	} else {
		options = append(options, "NOCREATEROLE")
	}

	if !plan.HasInheritOption.IsNull() && plan.HasInheritOption.ValueBool() {
		options = append(options, "INHERIT")
	} else {
		options = append(options, "NOINHERIT")
	}

	if !plan.HasReplicationOption.IsNull() && plan.HasReplicationOption.ValueBool() {
		options = append(options, "REPLICATION")
	} else {
		options = append(options, "NOREPLICATION")
	}

	if !plan.ConnectionLimit.IsNull() && plan.ConnectionLimit.ValueInt64() > -1 {
		options = append(options, fmt.Sprintf("CONNECTION LIMIT %d", plan.ConnectionLimit.ValueInt64()))
	} else {
		options = append(options, fmt.Sprintf("CONNECTION LIMIT %d", -1))
	}

	if !plan.IsValidUntil.IsNull() && len(plan.IsValidUntil.ValueString()) > 0 {
		options = append(options, fmt.Sprintf("VALID UNTIL '%s'", plan.IsValidUntil.ValueString()))
	} else {
		options = append(options, "VALID UNTIL 'infinity'")
	}

	return options
}
