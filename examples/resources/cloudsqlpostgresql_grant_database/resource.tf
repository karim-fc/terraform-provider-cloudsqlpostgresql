resource "cloudsqlpostgresql_grant_database" "default" {
  database = "test"
  role     = "u2"
  privileges = [
    {
      privilege = "CONNECT"
    }
  ]
}