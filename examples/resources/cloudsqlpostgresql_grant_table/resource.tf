resource "cloudsqlpostgresql_grant_table" "default" {
  table    = "table"
  database = "database"
  schema   = "schema"
  role     = "username"
  privileges = [
    {
      privilege = "SELECT"
    },
    {
      privilege = "UPDATE"
    }
  ]
}