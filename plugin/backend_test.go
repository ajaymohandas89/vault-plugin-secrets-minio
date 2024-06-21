package minio_test

import (
    "context"
    "testing"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
    minio "github.com/ajaymohandas89/vault-plugin-secrets-minio/plugin"
)
func TestMinioBackend(t *testing.T) {
    t.Run("Test Minio Backend Successfully Initialized", func(t *testing.T) {
        config := logical.TestBackendConfig()
        config.System = logical.TestSystemView()
        b, err := minio.Factory(context.Background(), config)
        require.NoError(t, err)
        require.NotNil(t, b)
    })
}

func getMinioBackend(tb testing.TB) (logical.Backend, error) {
    config := logical.TestBackendConfig()
    config.System = logical.TestSystemView()
    return minio.Factory(context.Background(), config)
}