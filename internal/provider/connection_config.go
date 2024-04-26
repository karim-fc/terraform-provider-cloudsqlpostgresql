package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

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

func (c *ConnectionConfig) Dsn() string {
	sslMode := "disable"
	if !c.SslMode.IsNull() {
		sslMode = c.SslMode.ValueString()
	}

	return fmt.Sprintf("host=%s dbname=%s user=%s password=%s sslmode=%s",
		c.ConnectionName.ValueString(),
		c.Database.ValueString(),
		c.Username.ValueString(),
		c.Password.ValueString(),
		sslMode)
}

func (c *ConnectionConfig) Id() string {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	json.NewEncoder(encoder).Encode(c)
	encoder.Close()
	return buf.String()
}

func connectionConfigSchemaAttribute() schema.Attribute {
	return schema.SingleNestedAttribute{
		Description:         "The connection properties for the Cloud SQL instance.",
		MarkdownDescription: "The connection properties for the Cloud SQL instance.",
		Required:            true,
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
			"database": schema.StringAttribute{
				Description:         "The database to connect to. Defaults to `postgres`.",
				MarkdownDescription: "The database to connect to. Defaults to `postgres`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("postgres"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
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
		PlanModifiers: []planmodifier.Object{
			objectplanmodifier.RequiresReplace(),
		},
	}
}
