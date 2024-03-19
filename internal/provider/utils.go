package provider

import (
	"context"
	"database/sql"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func fetchOidForRole(ctx context.Context, db *sql.DB, role string) (uint32, error) {
	var oid uint32
	err := db.QueryRowContext(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1", role).Scan(&oid)
	if err != nil {
		tflog.Error(ctx, "Error: "+err.Error())
		return 0, err
	}
	return oid, nil
}
