// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"hash/maphash"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_    provider.Provider = &CloudSqlPostgresqlProvider{}
	seed maphash.Seed      = maphash.MakeSeed()
)

type CloudSqlPostgresqlProvider struct {
	version string
}

type CloudSqlPostgresqlProviderModel struct {
	Connections map[string]ConnectionConfig `tfsdk:"connection_configs"`
}

type ConnectionConfig struct {
	ConnectionName types.String `tfsdk:"connection_name"`
	Database       types.String `tfsdk:"database"`
	Username       types.String `tfsdk:"username"`
	Password       types.String `tfsdk:"password"`
	Proxy          types.String `tfsdk:"proxy"`
	PrivateIP      types.Bool   `tfsdk:"private_ip"`
	PSC            types.Bool   `tfsdk:"psc"`
	SslMode        types.String `tfsdk:"ssl_mode"`
	// IAMAuthentication types.Bool   `tfsdk:"iam_authentication"` # Not supporting IAM authentication for now.
}

func (p *CloudSqlPostgresqlProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cloudsqlpostgresql"
	resp.Version = p.version
}

func (p *CloudSqlPostgresqlProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The cloudsqlpostgresql provider makes it possible to grant permissions to users and roles in a Google Cloud SQL Postgresql server. The development on this provider is still in progress...",
		MarkdownDescription: "The `cloudsqlpostgresql` provider makes it possible to grant permissions to users and roles in a Google Cloud SQL Postgresql server. The development on this provider is still in progress...",
		Attributes: map[string]schema.Attribute{
			"connection_configs": schema.MapNestedAttribute{
				Description:         "A map of connections of Postgresql database instances",
				MarkdownDescription: "A map of connections of Postgresql database instances",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"connection_name": schema.StringAttribute{
							MarkdownDescription: "The connection name of the Google Cloud SQL Postgresql instance. The `connection_name` format should be `<project>:<region>:<instance>`",
							Description:         "The connection name of the Google Cloud SQL Postgresql instance. The connection_name format should be <project>:<region>:<instance>",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^[a-z0-9\-]+\:[a-z0-9\-]+\:[a-z0-9\-]+$`),
									"`connection_name` must have the format of `<project>:<region>:<instance>`"),
							},
						},
						"database": schema.StringAttribute{
							Description:         "The database to connect to. Defaults to `postgres`.",
							MarkdownDescription: "The database to connect to. Defaults to `postgres`.",
							Optional:            true,
							// Computed:            true,
							// Default:             stringdefault.StaticString("postgres"),
						},
						"username": schema.StringAttribute{
							MarkdownDescription: "The username to use to authenticate with the Cloud SQL Postgresql instance",
							Description:         "The username to use to authenticate with the Cloud SQL Postgresql instance",
							Required:            true,
						},
						"password": schema.StringAttribute{
							MarkdownDescription: "The password to use to authenticate using the built-in database authentication",
							Description:         "The password to use to authenticate using the built-in database authentication",
							Required:            true,
							Sensitive:           true,
						},
						"proxy": schema.StringAttribute{
							MarkdownDescription: "Proxy socks url if used. Format needs to be `socks5://<ip>:<port>`",
							Description:         "Proxy socks url if used. Format needs to be socks5://<ip>:<port>",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^socks5:\/\/.*:\d+$`),
									"`proxy` must have the format of `socks5://<ip>:<port>`"),
							},
						},
						"private_ip": schema.BoolAttribute{
							MarkdownDescription: "Use the private IP address of the Cloud SQL Postgresql instance to connect to",
							Description:         "Use the private IP address of the Cloud SQL Postgresql instance to connect to",
							Optional:            true,
						},
						"psc": schema.BoolAttribute{
							MarkdownDescription: "Use the Private Service Connect endpoint of the Cloud SQL Postgresql instance to connect to",
							Description:         "Use the Private Service Connect endpoint of the Cloud SQL Postgresql instance to connect to",
							Optional:            true,
						},
						"ssl_mode": schema.StringAttribute{
							MarkdownDescription: "Determine the security of the connection to the Cloud SQL Postgresql instance",
							Description:         "Determine the security of the connection to the Cloud SQL Postgresql instance",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.RegexMatches(regexp.MustCompile(`^(disable|allow|prefer|require)$`),
									"`ssl_mode` must be a supported ssl mode. One of 'disable', 'allow', 'prefer' or 'require'"), // TODO: add support for verify-ca and verify-full
							},
						},
					},
				},
				Required: true,
			},
		},
	}
}

func (p *CloudSqlPostgresqlProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config CloudSqlPostgresqlProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	dbConfig := NewConfig()

	for k, cc := range config.Connections {
		connectionConfig := cc // to understand why, refer to https://stackoverflow.com/questions/44044245/register-multiple-routes-using-range-for-loop-slices-map/44045012#44045012
		connectionConfigsPath := path.Root("connection_configs").AtMapKey(k)
		if connectionConfig.ConnectionName.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("connection_name"),
				"Unknown Cloud SQL Postgresql connection name",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `connection_name`")
		}
		if connectionConfig.Username.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("username"),
				"Unknown Cloud SQL Postgresql username",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `username`")
		}
		if connectionConfig.Password.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("password"),
				"Unknown Cloud SQL Postgresql password",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `password`")
		}
		if connectionConfig.Database.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("database"),
				"Unknown Cloud SQL Postgresql database",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `database`")
		}
		if connectionConfig.Proxy.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("proxy"),
				"Unknown Cloud SQL Postgresql proxy",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `proxy`")
		}
		if connectionConfig.PrivateIP.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("private_ip"),
				"Unknown Cloud SQL Postgresql private ip flag",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `private_ip`")
		}
		if connectionConfig.PSC.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("psc"),
				"Unknown Cloud SQL Postgresql psc flag",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `psc`")
		}
		if connectionConfig.SslMode.IsUnknown() {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("ssl_mode"),
				"Unknown Cloud SQL Postgresql ssl mode flag",
				"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `ssl_mode`")
		}

		if resp.Diagnostics.HasError() {
			return
		}

		if connectionConfig.ConnectionName.IsNull() || connectionConfig.ConnectionName.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("connection_name"),
				"Missing Cloud SQL Postgresql connection name",
				"The provider cannot create the Cloud SQL Postgresql connection as there is a missing or empty value for the Cloud SQL Postgresql connection name. "+
					"Set the connection name value in the configuration.")
		}
		if connectionConfig.Username.IsNull() || connectionConfig.Username.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("username"),
				"Missing Cloud SQL Postgresql username",
				"The provider cannot create the Cloud SQL Postgresql connection as there is a missing or empty value for the Cloud SQL Postgresql username. "+
					"Set the username value in the configuration.")
		}
		if connectionConfig.Password.IsNull() || connectionConfig.Password.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(connectionConfigsPath.AtName("password"),
				"Missing Cloud SQL Postgresql password",
				"The provider cannot create the Cloud SQL Postgresql connection as there is a missing or empty value for the Cloud SQL Postgresql password. "+
					"Set the password value in the configuration.")
		}

		if resp.Diagnostics.HasError() {
			return
		}

		_, err := dbConfig.connectToPostgresql(ctx, &connectionConfig)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to create Cloud SQL Postgresql connection",
				"An unexpected error occurred when creating the Cloud SQL connection.\n\n"+
					"Error: "+err.Error(),
			)
			return
		}

		dbConfig.connections[k] = &connectionConfig
	}

	resp.ResourceData = dbConfig
	resp.DataSourceData = dbConfig
}

func (p *CloudSqlPostgresqlProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newDatabaseGrantResource,
		newSchemaGrantResource,
		newTableGrantResource,
		newRoleResource,
		newRoleGrantResource,
		newDefaultPrivilegesResource,
	}
}

func (p *CloudSqlPostgresqlProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &CloudSqlPostgresqlProvider{
			version: version,
		}
	}
}

func (c *ConnectionConfig) Dsn() string {
	sslMode := "disable"
	if !c.SslMode.IsNull() {
		sslMode = c.SslMode.ValueString()
	}

	database := "postgres"
	if !c.Database.IsNull() && c.Database.ValueString() != "" {
		database = c.Database.ValueString()
	}

	return fmt.Sprintf("host=%s dbname=%s user=%s password=%s sslmode=%s",
		c.ConnectionName.ValueString(),
		database,
		c.Username.ValueString(),
		c.Password.ValueString(),
		sslMode)
}

func (c *ConnectionConfig) DsnKey() string {
	var h maphash.Hash
	h.SetSeed(seed)
	_, _ = h.WriteString(fmt.Sprintf("DRIVERKEY:%s", c.DriverKey()))
	_, _ = h.WriteString(fmt.Sprintf("DSN:%s", c.Dsn()))
	return strconv.FormatUint(h.Sum64(), 10)
}

func (c *ConnectionConfig) DriverKey() string {
	var h maphash.Hash
	h.SetSeed(seed)
	_, _ = h.WriteString(fmt.Sprintf("PRIVATEIP:%t", c.PrivateIP.ValueBool()))
	_, _ = h.WriteString(fmt.Sprintf("PSC:%t", c.PSC.ValueBool()))
	_, _ = h.WriteString(fmt.Sprintf("PROXY:%s", c.Proxy.ValueString()))

	return strconv.FormatUint(h.Sum64(), 10)
}
