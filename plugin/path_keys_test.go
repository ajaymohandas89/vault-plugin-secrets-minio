package minio_test

import (
	"context"
	"math/rand"
	"testing"
	"time"

	minio "github.com/ajaymohandas89/vault-plugin-secrets-minio/plugin"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/minio/madmin-go/v3"
	"github.com/stretchr/testify/require"
)

const (
    TEST_STS_TTL    = 50
    userStoragePath = "users"
    letterBytes     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func TestPluginPathKeysCreateError(t *testing.T) {
    reqStorage := new(logical.InmemStorage)

    t.Run("Test Path Keys Api Generate Static Credentials Error When Role Not Found", func(t *testing.T) {
        resp, err := testPathKeysCreateStaticCredentials(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)
        require.Nil(t, resp)
    })

    t.Run("Test Path Keys Api Generate Static Credentials Error When Getting Minio Admin Client Returns Error", func(t *testing.T) {
        _, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "credential_type":  TEST_STATIC_CREDENTIAL_TYPE,
        })
        require.NoError(t, err)

        resp, err := testPathKeysCreateStaticCredentials(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)
        require.Nil(t, resp)
    })
}

func TestPluginPathKeysRevokeError(t *testing.T) {

    t.Run("Test Path Keys Api Revoke Error When Retrieving Role Details", func(t *testing.T) {
        reqStorage := new(logical.InmemStorage)
        reqStorage.Underlying().FailGet(true)
        resp, err := testPathKeysRevoke(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)
        require.Nil(t, resp)
    })

    t.Run("Test Path Keys Api Revoke Error When Updating UserInfoMap", func(t *testing.T) {
        reqStorage := new(logical.InmemStorage)
        resp, _ := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":      TEST_MAX_STS_TTL,
        })

        userInfo := minio.UserInfo{
            AccessKeyID:     "userAccesskey",
            SecretAccessKey: "secretAccessKey",
            PolicyName:      "policy",
            Status:          madmin.AccountEnabled,
            ExpirationDate:  time.Now(),
        }

        var userMap = make(map[string]minio.UserInfo)
        userMap[TEST_ROLE_NAME] = userInfo
        entry, _ := logical.StorageEntryJSON("users", userMap)
        reqStorage.Put(context.Background(), entry)

        reqStorage.Underlying().FailPut(true)
        resp, err := testPathKeysRevoke(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)
        require.Nil(t, resp)
    })
}

func testPathKeysCreateStaticCredentials(t *testing.T, s logical.Storage, roleName string) (*logical.Response, error) {
    t.Helper()
    b, _ := getMinioBackend(t)
    return b.HandleRequest(context.Background(), &logical.Request{
        ID:        generateRandomString(),
        Operation: logical.ReadOperation,
        Path:      "creds/" + roleName,
        Storage:   s,
    })
}

func testPathKeysCreateStsCredentials(t *testing.T, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
    t.Helper()
    b, _ := getMinioBackend(t)
    return b.HandleRequest(context.Background(), &logical.Request{
        ID:        generateRandomString(),
        Operation: logical.UpdateOperation,
        Path:      "sts/" + roleName,
        Data:      d,
        Storage:   s,
    })
}

func testPathKeysRevoke(t *testing.T, s logical.Storage, roleName string) (*logical.Response, error) {
    t.Helper()
    b, _ := getMinioBackend(t)
    return b.HandleRequest(context.Background(), &logical.Request{
        Operation: logical.DeleteOperation,
        Path:      "creds/" + roleName,
        Storage:   s,
    })
}

func generateRandomString() string {
    userNamePrefix := make([]byte, 20)
    for i := range userNamePrefix {
        userNamePrefix[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(userNamePrefix)
}