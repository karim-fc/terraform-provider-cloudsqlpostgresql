// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var (
	_ provider.Provider = &CloudSqlPostgresqlProvider{}
)

type CloudSqlPostgresqlProvider struct {
	version string
}

func (p *CloudSqlPostgresqlProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cloudsqlpostgresql"
	resp.Version = p.version
}

func (p *CloudSqlPostgresqlProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The cloudsqlpostgresql provider makes it possible to grant permissions to users and roles in a Google Cloud SQL Postgresql server. The development on this provider is still in progress...",
		MarkdownDescription: "The `cloudsqlpostgresql` provider makes it possible to grant permissions to users and roles in a Google Cloud SQL Postgresql server. The development on this provider is still in progress...",
	}
}

func (p *CloudSqlPostgresqlProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	dbConfig := NewConfig()
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
