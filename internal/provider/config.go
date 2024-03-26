package provider

import (
	"database/sql"
	"fmt"
	"sync"
)

type Config struct {
	dsnTemplate     string
	dbRegistry      map[string]*sql.DB
	dbRegistryMutex sync.Mutex
}

func NewConfig(dsnTemplate string) *Config {
	return &Config{
		dsnTemplate: dsnTemplate,
		dbRegistry:  make(map[string]*sql.DB),
	}
}

func (c *Config) connectToPostgresqlDb(dbName string) (*sql.DB, error) {
	dsn := fmt.Sprintf(c.dsnTemplate, "dbname="+dbName)
	return c.connectToPostgresql(dsn)
}

func (c *Config) connectToPostgresqlNoDb() (*sql.DB, error) {
	dsn := fmt.Sprintf(c.dsnTemplate, "")
	return c.connectToPostgresql(dsn)
}

func (c *Config) connectToPostgresql(dsn string) (*sql.DB, error) {
	c.dbRegistryMutex.Lock()
	defer c.dbRegistryMutex.Unlock()

	if c.dbRegistry[dsn] != nil {
		return c.dbRegistry[dsn], nil
	}

	db, err := sql.Open("cloudsql-postgres", dsn)
	if err != nil {
		return nil, err
	}
	c.dbRegistry[dsn] = db
	return c.dbRegistry[dsn], nil
}
