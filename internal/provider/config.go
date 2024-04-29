package provider

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sync"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/net/proxy"
)

type Config struct {
	dbRegistry      map[string]*sql.DB
	dbRegistryMutex sync.Mutex
	dbDrivers       map[string]bool
	dbDriversMutex  sync.Mutex
	connections     map[string]*ConnectionConfig
}

func NewConfig() *Config {
	return &Config{
		dbRegistry:  make(map[string]*sql.DB),
		dbDrivers:   make(map[string]bool),
		connections: make(map[string]*ConnectionConfig),
	}
}

func (c *Config) connectToPostgresql(ctx context.Context, cc *ConnectionConfig) (*sql.DB, error) {
	c.dbRegistryMutex.Lock()
	defer c.dbRegistryMutex.Unlock()

	key := cc.DsnKey()

	if c.dbRegistry[key] != nil {
		return c.dbRegistry[key], nil
	}

	err := c.registerDriver(ctx, cc)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(cc.DriverKey(), cc.Dsn())
	if err != nil {
		return nil, err
	}

	c.dbRegistry[key] = db
	return c.dbRegistry[key], nil
}

func (c *Config) registerDriver(ctx context.Context, cc *ConnectionConfig) error {
	c.dbDriversMutex.Lock()
	defer c.dbDriversMutex.Unlock()

	key := cc.DriverKey()

	if c.dbDrivers[key] {
		return nil
	}

	var (
		dialOptions []cloudsqlconn.DialOption
		options     []cloudsqlconn.Option
	)

	if cc.PrivateIP.ValueBool() {
		dialOptions = append(dialOptions, cloudsqlconn.WithPrivateIP())
	}

	if cc.PSC.ValueBool() {
		dialOptions = append(dialOptions, cloudsqlconn.WithPSC())
	}

	options = append(options, cloudsqlconn.WithDefaultDialOptions(dialOptions...))

	if !cc.Proxy.IsNull() {
		options = append(options, cloudsqlconn.WithDialFunc(createDialer(cc.Proxy.ValueString(), ctx)))
	}

	_, err := pgxv4.RegisterDriver(key, options...)
	if err != nil {
		return err
	}

	c.dbDrivers[key] = true
	return nil
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
