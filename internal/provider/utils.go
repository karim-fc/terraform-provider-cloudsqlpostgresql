package provider

import (
	"context"
	"database/sql"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func txRollback(ctx context.Context, tx *sql.Tx) {
	err := tx.Rollback()
	if err != nil {
		tflog.Error(ctx, "Unexpected error while rollback: "+err.Error())
	}
}
