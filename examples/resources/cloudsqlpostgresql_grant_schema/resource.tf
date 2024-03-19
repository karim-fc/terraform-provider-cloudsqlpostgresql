resource "cloudsqlpostgresql_grant_database" "default" {
  database = "database"
  schema   = "schema"
  role     = "username"
  privileges = [
    {
      privilege = "USAGE"
    }
  ]
}