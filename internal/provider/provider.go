// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/net/proxy"
)

var (
	_ provider.Provider = &CloudSqlPostgresqlProvider{}
)

type CloudSqlPostgresqlProvider struct {
	version string
}

type CloudSqlPostgresqlProviderModel struct {
	ConnectionName types.String `tfsdk:"connection_name"`
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
			"connection_name": schema.StringAttribute{
				MarkdownDescription: "The connection name of the Google Cloud SQL Postgresql instance. The `connection_name` format should be `<project>:<region>:<instance>`",
				Description:         "The connection name of the Google Cloud SQL Postgresql instance. The connection_name format should be <project>:<region>:<instance>",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^[a-z0-9\-]+\:[a-z0-9\-]+\:[a-z0-9\-]+$`),
						"`connection_name` must have the format of `<project>:<region>:<instance>`"),
				},
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "The username to use to authenticate with the Cloud SQL Postgresql instance",
				Description:         "The username to use to authenticate with the Cloud SQL Postgresql instance",
				Optional:            true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "The password to use to authenticate using the built-in database authentication",
				Description:         "The password to use to authenticate using the built-in database authentication",
				Optional:            true,
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
			// "iam_authentication": schema.BoolAttribute{
			// 	MarkdownDescription: "Enables the use of IAM authentication. The `password` field needs to be used to fill in the access token",
			// 	Optional:            true,
			// },
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
	}
}

func (p *CloudSqlPostgresqlProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config CloudSqlPostgresqlProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.ConnectionName.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("connection_name"),
			"Unknown Cloud SQL Postgresql connection name",
			"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `connection_name`")
	}

	// username and password are required for now as long IAM authentication is not supported.
	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("username"),
			"Unknown Cloud SQL Postgresql username",
			"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `username`")
	}

	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("password"),
			"Unknown Cloud SQL Postgresql username",
			"The provider cannot create the Cloud SQL Postgresql client as there is an unknown configuration value for the `password`")
	}

	if resp.Diagnostics.HasError() {
		return
	}

	connectionName := os.Getenv("CLOUDSQL_POSTGRES_CONNECTION_NAME")
	username := os.Getenv("CLOUDSQL_POSTGRES_USERNAME")
	password := os.Getenv("CLOUDSQL_POSTGRES_PASSWORD")

	if !config.ConnectionName.IsNull() {
		connectionName = config.ConnectionName.ValueString()
	}

	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}

	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}

	if connectionName == "" {
		resp.Diagnostics.AddAttributeError(path.Root("connection_name"),
			"Missing Cloud SQL Postgresql connection name",
			"The provider cannot create the Cloud SQL Postgresql connection as there is a missing or empty value for the Cloud SQL Postgresql connection name. "+
				"Set the connection name value in the configuration or use the CLOUDSQL_POSTGRES_CONNECTION_NAME environment variable. ")
	}

	if username == "" {
		resp.Diagnostics.AddAttributeError(path.Root("username"),
			"Missing Cloud SQL Postgresql username",
			"The provider cannot create the Cloud SQL Postgresql connection as there is a missing or empty value for the Cloud SQL Postgresql username. "+
				"Set the username value in the configuration or use the CLOUDSQL_POSTGRES_USERNAME environment variable.")
	}

	if password == "" {
		resp.Diagnostics.AddAttributeError(path.Root("password"),
			"Missing Cloud SQL Postgresql password",
			"The provider cannot create the Cloud SQL Postgresql connection as there is a missing or empty value for the Cloud SQL Postgresql password. "+
				"Set the password value in the configuration or use the CLOUDSQL_POSTGRES_PASSWORD environment variable.")
	}

	if resp.Diagnostics.HasError() {
		return
	}

	sslMode := "disable"
	if !config.SslMode.IsNull() {
		sslMode = config.SslMode.ValueString()
	}

	var dialOptions []cloudsqlconn.DialOption
	// dialOptions = append(dialOptions, cloudsqlconn.WithDialIAMAuthN(username == "")) // enable IAM authentication when username is not set

	if config.PrivateIP.ValueBool() {
		dialOptions = append(dialOptions, cloudsqlconn.WithPrivateIP())
	}

	if config.PSC.ValueBool() {
		dialOptions = append(dialOptions, cloudsqlconn.WithPSC())
	}

	var options []cloudsqlconn.Option

	options = append(options, cloudsqlconn.WithDefaultDialOptions(dialOptions...))

	if !config.Proxy.IsNull() {
		tflog.Debug(ctx, "`proxy` is not null")
		options = append(options, cloudsqlconn.WithDialFunc(createDialer(config.Proxy.ValueString(), ctx)))
	}

	_, err := pgxv4.RegisterDriver("cloudsql-postgres", options...)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to create Cloud SQL Postgresql connection",
			"An unexpected error occurred when creating the Cloud SQL connection.\n\n"+
				"Error: "+err.Error(),
		)
	}

	dsnTemplate := fmt.Sprintf("host=%s %%s user=%s password=%s sslmode=%s", connectionName, username, password, sslMode)

	dbConfig := NewConfig(dsnTemplate)

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

func createDialer(proxyInput string, ctxProvider context.Context) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		tflog.Info(ctxProvider, "Creating Dialer with proxy: "+proxyInput)
		if len(proxyInput) == 0 {
			return nil, fmt.Errorf("proxy is empty")
		}

		proxyURL, err := url.Parse(proxyInput)
		if err != nil {
			return nil, err
		}
		d, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			return nil, err
		}

		if xd, ok := d.(proxy.ContextDialer); ok {
			return xd.DialContext(ctx, network, address)
		}

		tflog.Warn(ctxProvider, "net.Conn created without context.Context")
		return d.Dial(network, address) // TODO: force use of context?
	}
}
