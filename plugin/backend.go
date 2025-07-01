package minio

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "sync"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"

    "github.com/minio/madmin-go/v3"
    "github.com/minio/minio-go/v7/pkg/credentials"
)

type minioBackend struct {
    *framework.Backend

    client *madmin.AdminClient

    clientMutex sync.RWMutex

    userCredsMap map[string][]UserInfo

    userCredsMapMutex sync.RWMutex
}

// Factory returns a configured instance of the minio backend
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
    b := Backend()
    if err := b.Setup(ctx, c); err != nil {
    return nil, err
    }

    // Load user credentials map from vault persistent storage
    b.Logger().Info("Retrieving user static credentials from vault persistent storage")
    if err := b.loadUserStaticCredentialsFromVault(ctx, c.StorageView) ; err != nil {
        b.Logger().Error("failed to get user entry map from persistent storage!", err)
        return nil, err
    }

    b.Logger().Info("Plugin successfully initialized")
    return b, nil
}

func (b *minioBackend) loadUserStaticCredentialsFromVault(ctx context.Context, storage logical.Storage) error {
    entry, err := storage.Get(ctx, userStoragePath)
    if err != nil {
        return fmt.Errorf("failed to get user credentials map from persistent storage: %v", err)
    }
    
    b.userCredsMapMutex.Lock()
    defer b.userCredsMapMutex.Unlock()

    if entry == nil {
        //Initialize the user credentials map if its being accessed for the first time
        b.userCredsMap = make(map[string][]UserInfo)
        return nil
    }

    if err := entry.DecodeJSON(&b.userCredsMap); err != nil {
        return fmt.Errorf("failed to decode user credentials map %v", err)
    }
    return nil
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
        err = errors.New("endpoint not set when trying to create new madmin client")
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

    creds := credentials.NewStaticV4(c.AccessKeyId, c.SecretAccessKey, "")
    opts := &madmin.Options{
        Creds: creds,
        Secure: true,
    }
    client, err := madmin.NewWithOptions(c.Endpoint, opts)
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
Backend that returns secret credentials for clients using MinIO.
`