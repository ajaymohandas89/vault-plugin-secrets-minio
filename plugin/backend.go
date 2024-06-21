package minio

import (
    "context"
    "errors"
    "strings"
    "sync"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"

    "github.com/minio/madmin-go/v3"
)

type minioBackend struct {
    *framework.Backend

    client *madmin.AdminClient

    clientMutex sync.RWMutex
}

// Factory returns a configured instance of the minio backend
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
    b := Backend()
    if err := b.Setup(ctx, c); err != nil {
    return nil, err
    }

    b.Logger().Info("Plugin successfully initialized")
    return b, nil
}

// Backend returns a configured minio backend
func Backend() *minioBackend {
    var b minioBackend

    b.Backend = &framework.Backend{
    BackendType: logical.TypeLogical,
    Help: strings.TrimSpace(minioHelp),
    PathsSpecial: &logical.Paths{
        SealWrapStorage: []string{
            configStoragePath,
            "roles/*",
            userStoragePath,
        },
    },
    Paths: []*framework.Path{
        // path_config.go
        // ^config
        b.pathConfigCRUD(),

        // path_roles.go
        // ^roles (LIST)
        b.pathRoles(),
        // ^roles/<role> 
        b.pathRolesCRUD(),

        // path_keys.go
        // ^creds/<role>
        // ^sts/<role>
        b.pathKeysRead(),
    },
    }

    b.client = (*madmin.AdminClient)(nil)

    return &b
}

// Convenience function to get a new madmin client
func (b *minioBackend) getMadminClient(ctx context.Context, s logical.Storage) (*madmin.AdminClient, error) {

    b.Logger().Debug("getMadminClient, getting clientMutext.RLock")
    b.clientMutex.Lock()
    defer b.clientMutex.Unlock()

    if b.client != nil {
        b.Logger().Debug("Already have client, returning")
        return b.client, nil
    }

    // Don't have client, look up configuration and gin up new client
    b.Logger().Info("getMadminClient, need new client and looking up config")

    c, err := b.GetConfig(ctx, s)
    if err != nil {
        b.Logger().Error("Error fetching config in getMadminClient", "error", err)
        return nil, err
    }

    if c.Endpoint == "" {
        err = errors.New("Endpoint not set when trying to create new madmin client")
        b.Logger().Error("Error", "error", err)
        return nil, err
    }

    if c.AccessKeyId == "" {
        err = errors.New("AccessKeyId not set when trying to create new madmin client")
        b.Logger().Error("Error", "error", err)
        return nil, err
    }

    if c.SecretAccessKey == "" {
        err = errors.New("SecretAccessKey not set when trying to create new madmin client")
        b.Logger().Error("Error", "error", err)
        return nil, err
    }

    client, err := madmin.New(c.Endpoint, c.AccessKeyId, c.SecretAccessKey, c.UseSSL)
    if err != nil {
        b.Logger().Error("Error getting new madmin client", "error", err)
        return nil, err
    }
    
    b.client = client
    return b.client, nil
}

// Call this to invalidate the current backend client
func (b *minioBackend) invalidateMadminClient() {
    b.Logger().Debug("invalidateMadminClient")
    
    b.clientMutex.Lock()
    defer b.clientMutex.Unlock()

    b.client = nil
}

const minioHelp = `
The minio secret backend returns dynamic STS credentials to access data on Minio server.
`