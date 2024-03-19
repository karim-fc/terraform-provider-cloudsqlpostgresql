terraform {
  required_providers {
    cloudsqlpostgresql = {
      source = "devoteamgcloud/cloudsqlpostgresql"
    }
  }
}

provider "cloudsqlpostgresql" {
  connection_name = "project:region:instance"
  username        = "username"
  password        = "password"
  proxy           = "socks5://<socks5-ip>:1080"
  psc             = true
}
