package minio

import (
    "context"
    "strings"
    "fmt"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

const (
    configStoragePath = "config/root"
)

type Config struct {
    Endpoint string `json:"endpoint"`
    AccessKeyId string `json:"accessKeyId"`
    SecretAccessKey string `json:"secretAccessKey"`
    UseSSL bool `json:"useSSL"`
    Configured bool `json:"is_configured"`
}

// Define the CRU functions for the config path
func (b *minioBackend) pathConfigCRUD() *framework.Path {
    return &framework.Path{
    Pattern: configStoragePath,
    HelpSynopsis: "Configure the Minio connection.",
    HelpDescription: "Use this endpoint to set the Minio endpoint, accessKeyId, secretAccessKey and SSL settings.",

    Fields: map[string]*framework.FieldSchema{
        "endpoint": &framework.FieldSchema{
        Type: framework.TypeString,
        Description: "The Minio server endpoint.",
        },
        "accessKeyId": &framework.FieldSchema{
        Type: framework.TypeString,
        Description: "The Minio administrative key ID.",
        },
        "secretAccessKey": &framework.FieldSchema{
        Type: framework.TypeString,
        Description: "The Minio administrative secret access key.",
        },
        "useSSL": &framework.FieldSchema{
        Type: framework.TypeBool,
        Description: "(Optional, default `false`) Use SSL to connect to the Minio server.",
        },
    },

    Operations: map[logical.Operation]framework.OperationHandler{
        logical.ReadOperation: &framework.PathOperation{
            Callback: b.pathConfigRead,
        },
        logical.UpdateOperation: &framework.PathOperation{
            Callback: b.pathConfigUpdate,
        },
        logical.DeleteOperation: &framework.PathOperation{
            Callback: b.pathConfigDelete,
        },
    },
    }
}

// Read the current configuration
func (b *minioBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
    c, err := b.GetConfig(ctx, req.Storage);
    if err != nil {
        return nil, err
    }

    return &logical.Response{
    Data: map[string]interface{}{
        "endpoint": c.Endpoint,
        "accessKeyId": c.AccessKeyId,
        "secretAccessKey": c.SecretAccessKey,
        "useSSL": c.UseSSL,
    },
    }, nil
}

// Update the configuration
func (b *minioBackend) pathConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    c, err := b.GetConfig(ctx, req.Storage);
    if err != nil {
        return nil, err
    }

    // Update the internal configuration
    changed, err := c.Update(d)
    if err != nil {
        return nil, err
    }

    // If we changed the configuration, store it
    if changed {
        // Make a new storage entry
        entry, err := logical.StorageEntryJSON(configStoragePath, c)
        if err != nil {
            return nil, fmt.Errorf("failed to generate JSON configuration: %v", err)
        }

        // And store it
        if err := req.Storage.Put(ctx, entry); err != nil {
            return nil, fmt.Errorf("failed to persist configuration: %v", err)
        }

    }

    // Destroy any old client which may exist so we get a new one
    // with the next request
    b.invalidateMadminClient()

    return nil, nil
}

func (b *minioBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    err := req.Storage.Delete(ctx, configStoragePath)

    if err == nil {
        b.invalidateMadminClient()
        return nil, nil
    }

    return nil, fmt.Errorf("failed to delete configuration: %v", err)
}

func (c *Config) Update(d *framework.FieldData) (bool, error) {
    if d == nil {
        return false, logical.CodedError(400, "Bad Request Error")
    }

    changed := false

    keys := []string{"endpoint", "accessKeyId", "secretAccessKey"}

    for _, key := range keys {
    if v, ok := d.GetOk(key); ok {
        nv := strings.TrimSpace(v.(string))

        switch key {
        case "endpoint":
        c.Endpoint = nv
        c.Configured = true
        changed = true
        case "accessKeyId":
        c.AccessKeyId = nv
        c.Configured = true
        changed = true
        case "secretAccessKey":
        c.SecretAccessKey = nv
        c.Configured = true
        changed = true
        }
    }
    }

    if v, ok := d.GetOk("useSSL"); ok {
    nv := v.(bool)
    c.UseSSL = nv
    c.Configured = true
    changed = true
    }

    return changed, nil
}

func (b *minioBackend) GetConfig(ctx context.Context, s logical.Storage) (*Config, error) {
    c := DefaultConfig()

    entry, err := s.Get(ctx, configStoragePath);
    if err != nil {
        return nil, fmt.Errorf("failed to get configuration from backend: %v", err)
    }

    if entry == nil || len(entry.Value) == 0 {
        return c, nil
    }

    if err := entry.DecodeJSON(&c); err != nil {
        return nil, fmt.Errorf("failed to decode configuration: %v", err)
    }

    return c, nil
}

func DefaultConfig() *Config {
    return &Config{
    Endpoint: "",
    AccessKeyId: "",
    SecretAccessKey: "",
    UseSSL: false,
    Configured: false,
    }
}