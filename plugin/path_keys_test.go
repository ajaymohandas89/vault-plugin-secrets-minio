package minio_test

import (
	"context"
	"math/rand"
	"testing"
	"time"

	minio "github.com/ajaymohandas89/vault-plugin-secrets-minio/plugin"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/minio/madmin-go/v4"
	"github.com/stretchr/testify/require"
)

const (
	TEST_STS_TTL        = 50
	userStoragePath     = "users"
	letterBytes         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	expiredUserCredPath = "expiredUserCred"
)

func TestPluginPathKeysSuccess_StaticCredentials(t *testing.T) {
	t.Skip("skipping test when building, comment this line to test path_keys")
	reqStorage := new(logical.InmemStorage)
	minioBackend := minio.Backend()
	t.Run("Test Path Keys Api Generate Credentials With No Error", func(t *testing.T) {
		err := testConfigCreateOrUpdate(t, reqStorage, map[string]interface{}{
			"endpoint":        TEST_APP_OSS_ENDPOINT,
			"accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
			"secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
			"useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
		})
		require.NoError(t, err)

		_, err = testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"role":            TEST_ROLE_NAME,
			"policy_name":     TEST_POLICY_NAME,
			"credential_type": TEST_STATIC_CREDENTIAL_TYPE,
			"max_ttl":         "3m",
			"grace_period":    "1m",
		})
		require.NoError(t, err)

		//Generate user static credentials for the first time
		var userMap = make(map[string][]minio.UserInfo)
		minioBackend.SetuserCredsMap(userMap)
		resp, _ := minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["policy_name"])
		require.NotEmpty(t, resp.Data["userAccountStatus"])

		resp, err = minioBackend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.Nil(t, resp)

		//Generate user static credentials for the first time after revoking
		resp, _ = minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["policy_name"])
		require.NotEmpty(t, resp.Data["userAccountStatus"])

		//Verify if vault storage has 1 credentials
		entry, _ := reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 1, len(userMap[TEST_ROLE_NAME]))

		//Requesting for user static credentials for the second time
		//Return same credentials since it has not expired
		resp, _ = minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["policy_name"])
		require.NotEmpty(t, resp.Data["userAccountStatus"])

		//Verify if vault storage has 1 credentials
		entry, _ = reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 1, len(userMap[TEST_ROLE_NAME]))

		//Updating the credentials expiration date
		creds := userMap[TEST_ROLE_NAME][0]
		creds.CreationTime = time.Now().Add(time.Duration(-3) * time.Minute)

		userMap[TEST_ROLE_NAME] = []minio.UserInfo{creds}

		minioBackend.SetuserCredsMap(userMap)

		//Requesting for user static credentials for the third time
		//Since credential expired will create new and return new credential
		resp, _ = minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["policy_name"])
		require.NotEmpty(t, resp.Data["userAccountStatus"])

		entry, _ = reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 2, len(userMap[TEST_ROLE_NAME]))

		//Updating the credentials expiration date
		creds = userMap[TEST_ROLE_NAME][0]
		creds.CreationTime = time.Now().Add(time.Duration(-5) * time.Minute)
		userMap[TEST_ROLE_NAME] = []minio.UserInfo{creds}

		minioBackend.SetuserCredsMap(userMap)

		//Requesting for user static credentials for the 4th time
		//Vault has 1 active and 1 expired credentials
		//Expired credentials are deleted as request is beyond max ttl and grace period
		//Return active credential
		resp, _ = minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["policy_name"])
		require.NotEmpty(t, resp.Data["userAccountStatus"])

		//Verify if vault storage has 1 credentials
		entry, _ = reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 1, len(userMap[TEST_ROLE_NAME]))

		//Requesting user credentials, return active credentials
		resp, _ = minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["policy_name"])
		require.NotEmpty(t, resp.Data["userAccountStatus"])

		//Verify if vault storage has 1 credentials
		entry, _ = reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 1, len(userMap[TEST_ROLE_NAME]))

		//Requesting user credentials, return active credentials
		minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)

		//Verify if vault storage has 1 credentials
		entry, _ = reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 1, len(userMap[TEST_ROLE_NAME]))

		_, err = minioBackend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "roles/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)

		//Verify if vault storage has 0 credentials
		entry, _ = reqStorage.Get(context.Background(), userStoragePath)
		entry.DecodeJSON(&userMap)
		require.Equal(t, 0, len(userMap[TEST_ROLE_NAME]))

	})
}

func TestPluginPathKeysSuccess_StSCredentials(t *testing.T) {
	t.Skip("skipping test when building, comment this line to test path_keys")
	reqStorage := new(logical.InmemStorage)
	t.Run("Test Path Keys Api Generate Credentials With No Error", func(t *testing.T) {
		err := testConfigCreateOrUpdate(t, reqStorage, map[string]interface{}{
			"endpoint":        TEST_APP_OSS_ENDPOINT,
			"accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
			"secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
			"useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
		})
		require.NoError(t, err)

		_, err = testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"role":             TEST_ROLE_NAME,
			"policy_name":      TEST_POLICY_NAME,
			"credential_type":  TEST_STS_CREDENTIAL_TYPE,
			"user_name_prefix": TEST_USERNAME_PREFIX,
			"max_sts_ttl":      "1h",
		})
		require.NoError(t, err)

		//Create STS credentials when ttl is less than max_sts_ttl
		resp, err := testPathKeysCreateStsCredentials(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"ttl": "30m",
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["sessionToken"])

		//Create STS credentials when ttl is greater than max_sts_ttl
		resp, err = testPathKeysCreateStsCredentials(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"ttl": "4h",
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["sessionToken"])

		//Create STS credentials when ttl is not supplied
		resp, err = testPathKeysCreateStsCredentials(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Data["accessKeyId"])
		require.NotEmpty(t, resp.Data["secretAccessKey"])
		require.NotEmpty(t, resp.Data["ttl"])
		require.NotEmpty(t, resp.Data["sessionToken"])
	})
}

func TestPluginPathKeysRevoke_Success_No_Creds_Present(t *testing.T) {
	reqStorage := new(logical.InmemStorage)
	minioBackend := minio.Backend()
	t.Run("Test Path Keys Api Generate Credentials With No Error", func(t *testing.T) {
		err := testConfigCreateOrUpdate(t, reqStorage, map[string]interface{}{
			"endpoint":        TEST_APP_OSS_ENDPOINT,
			"accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
			"secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
			"useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
		})
		require.NoError(t, err)

		_, err = testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"role":            TEST_ROLE_NAME,
			"policy_name":     TEST_POLICY_NAME,
			"credential_type": TEST_STATIC_CREDENTIAL_TYPE,
			"max_ttl":         "3m",
			"grace_period":    "1m",
		})
		require.NoError(t, err)

		resp, err := minioBackend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.Nil(t, resp)
	})
}

func TestPluginPathKeysCreateError_When_Role_NotFound(t *testing.T) {
	reqStorage := new(logical.InmemStorage)

	t.Run("Test Path Keys Api Generate Static Credentials Error When Role Not Found", func(t *testing.T) {
		minioBackend := minio.Backend()
		resp, err := minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestPluginPathKeysCreateError_When_Minio_Root_OSS_Endpoint_Not_Set(t *testing.T) {
	reqStorage := new(logical.InmemStorage)
	t.Run("Test Path Keys Api Generate Static Credentials Error ", func(t *testing.T) {
		minioBackend := minio.Backend()
		_, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"role":             TEST_ROLE_NAME,
			"user_name_prefix": TEST_USERNAME_PREFIX,
			"policy_name":      TEST_POLICY_NAME,
			"credential_type":  TEST_STATIC_CREDENTIAL_TYPE,
		})
		require.NoError(t, err)

		d := map[string]interface{}{
			"accessKeyId":     TEST_APP_OSS_ACCESS_KEY_ID,
			"secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
			"useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
		}
		minioBackend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configStoragePath,
			Storage:   reqStorage,
			Data:      d,
		})

		resp, err := minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestPluginPathKeysCreateError_When_Minio_Root_OSS_AccessKey_Not_Set(t *testing.T) {
	reqStorage := new(logical.InmemStorage)
	t.Run("Test Path Keys Api Generate Static Credentials Error When Minio Root AccessKey Not Set", func(t *testing.T) {
		minioBackend := minio.Backend()
		_, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"role":             TEST_ROLE_NAME,
			"user_name_prefix": TEST_USERNAME_PREFIX,
			"policy_name":      TEST_POLICY_NAME,
			"credential_type":  TEST_STATIC_CREDENTIAL_TYPE,
		})
		require.NoError(t, err)

		d := map[string]interface{}{
			"endpoint":        TEST_APP_OSS_ENDPOINT,
			"secretAccessKey": TEST_APP_OSS_SECRET_ACCESS_KEY,
			"useSSL":          TEST_OSS_ENDPOINT_USE_SSL,
		}
		minioBackend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configStoragePath,
			Storage:   reqStorage,
			Data:      d,
		})

		resp, err := minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
		require.Error(t, err)
		require.Nil(t, resp)
	})

}

func TestPluginPathKeysCreateError_When_Minio_Root_OSS_SecretAccessKey_Not_Set(t *testing.T) {
	reqStorage := new(logical.InmemStorage)
	t.Run("Test Path Keys Api Generate Static Credentials Error When Minio Root OSS SecretAccessKey Not Set", func(t *testing.T) {
		minioBackend := minio.Backend()
		_, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
			"role":             TEST_ROLE_NAME,
			"user_name_prefix": TEST_USERNAME_PREFIX,
			"policy_name":      TEST_POLICY_NAME,
			"credential_type":  TEST_STATIC_CREDENTIAL_TYPE,
		})
		require.NoError(t, err)

		d := map[string]interface{}{
			"endpoint":    TEST_APP_OSS_ENDPOINT,
			"accessKeyId": TEST_APP_OSS_ACCESS_KEY_ID,
			"useSSL":      TEST_OSS_ENDPOINT_USE_SSL,
		}
		minioBackend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configStoragePath,
			Storage:   reqStorage,
			Data:      d,
		})

		resp, err := minioBackend.HandleRequest(context.Background(), &logical.Request{
			ID:        generateRandomString(),
			Operation: logical.ReadOperation,
			Path:      "creds/" + TEST_ROLE_NAME,
			Storage:   reqStorage,
		})
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
			CreationTime:    time.Now(),
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
