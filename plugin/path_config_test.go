package minio_test

import (
    "context"
    "fmt"
    "testing"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
)

const (
    TEST_APP_OSS_ENDPOINT          = "oss-test.com"
    TEST_APP_OSS_ACCESS_KEY_ID     = "test-access-key-id"
    TEST_APP_OSS_SECRET_ACCESS_KEY = "test-secret-access-key"
    TEST_OSS_ENDPOINT_USE_SSL      = true
    configStoragePath = "config/root"
)

func TestConfigSuccess(t *testing.T) {
    reqStorage := new(logical.InmemStorage)

    t.Run("Test Plugin Configuration", func(t *testing.T) {
        err := testConfigCreateOrUpdate(t, reqStorage, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.NoError(t, err)

        err = testConfigRead(t, reqStorage, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.NoError(t, err)

        // Updating the config
        err = testConfigCreateOrUpdate(t, reqStorage, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     "new-access-kye-id",
            "secretAccessKey": "new-secret-access-key",
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.NoError(t, err)

        err = testConfigRead(t, reqStorage, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     "new-access-kye-id",
            "secretAccessKey": "new-secret-access-key",
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.NoError(t, err)

        resp, err := testConfigDelete(t, reqStorage)

        require.NoError(t, err)
        require.Nil(t, resp.Error())
    })
}

func TestConfigReadError(t *testing.T) {
    reqStorage := new(logical.InmemStorage)
    
    t.Run("Test Plugin Configuration Reading Empty Configuration", func(t *testing.T) {
        err := testConfigRead(t, reqStorage, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     "new-access-kye-id",
            "secretAccessKey": "new-secret-access-key",
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.Error(t, err)
    })

    t.Run("Test Plugin Configuration When Actual Expected Data Not Match", func(t *testing.T) {
        err := testConfigCreateOrUpdate(t, reqStorage, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.NoError(t, err)

        err = testConfigRead(t, reqStorage, map[string]interface{}{
            "endpoint": TEST_APP_OSS_ENDPOINT,
            "useSSL":   TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.Error(t, err)
    })

    t.Run("Test Plugin Configuration When Read Api Returns Error", func(t *testing.T) {
        s := &logical.InmemStorage{}
        err := testConfigCreateOrUpdate(t, s, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.NoError(t, err)

        s.Underlying().FailGet(true)
        err = testConfigRead(t, s, map[string]interface{}{
            "endpoint": TEST_APP_OSS_ENDPOINT,
            "useSSL":   TEST_OSS_ENDPOINT_USE_SSL,
        })
        require.Error(t, err)
    })
}

func TestConfigWriteError(t *testing.T) {
    s := new(logical.InmemStorage)

    t.Run("Test Plugin Configuration When Update Api Returns Error", func(t *testing.T) {
        s.Underlying().FailPut(true)
        err := testConfigCreateOrUpdate(t, s, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.Error(t, err)
    })

    t.Run("Test Plugin Update Old Configuration Returns Get Api Error ", func(t *testing.T) {
        s.Underlying().FailPut(false)
        err := testConfigCreateOrUpdate(t, s, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.Nil(t, err)

        s.Underlying().FailGet(true)
        err = testConfigCreateOrUpdate(t, s, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     "test_new_access_id",
            "secretAccessKey": "test_new_secret_access_id",
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.Error(t, err)
    })
}

func TestConfigDeleteError(t *testing.T) {
    s := new(logical.InmemStorage)

    t.Run("Test Plugin Configuration When Delete Api Returns Error", func(t *testing.T) {
        err := testConfigCreateOrUpdate(t, s, map[string]interface{}{
            "endpoint":        TEST_APP_OSS_ENDPOINT,
            "accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
            "secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
            "useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
        })

        require.Nil(t, err)

        s.Underlying().FailDelete(true)
        resp, err := testConfigDelete(t, s)

        require.Error(t, err)
        require.Nil(t, resp)
    })
}

func testConfigDelete(t *testing.T, s logical.Storage) (*logical.Response, error) {
    b, _ := getMinioBackend(t)
    return b.HandleRequest(context.Background(), &logical.Request{
        Operation: logical.DeleteOperation,
        Path:      configStoragePath,
        Storage:   s,
    })
}

func testConfigCreateOrUpdate(t *testing.T, s logical.Storage, d map[string]interface{}) error {
    b, _ := getMinioBackend(t)
    resp, err := b.HandleRequest(context.Background(), &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      configStoragePath,
        Data:      d,
        Storage:   s,
    })

    if err != nil {
        return err
    }

    if resp != nil && resp.IsError() {
        return resp.Error()
    }
    return nil
}

func testConfigRead(t *testing.T, s logical.Storage, expected map[string]interface{}) error {
    b, _ := getMinioBackend(t)
    resp, err := b.HandleRequest(context.Background(), &logical.Request{
        Operation: logical.ReadOperation,
        Path:      configStoragePath,
        Storage:   s,
    })

    if err != nil {
        return err
    }

    if len(expected) != len(resp.Data) {
        return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
    }

    for key, expectedVal := range expected {
        actualVal, _ := resp.Data[key]

        if expectedVal != actualVal {
            return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, key, actualVal, actualVal)
        }
    }

    return nil
}