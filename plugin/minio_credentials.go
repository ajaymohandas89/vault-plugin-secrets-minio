package minio

import (
    "context"
    "strings"
    "time"

    "encoding/base64"

    "fmt"

    uuid "github.com/hashicorp/go-uuid"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/minio/madmin-go/v3"
    cr "github.com/minio/minio-go/v7/pkg/credentials"
)

const (
    userStoragePath      = "users"
    minioSecretKeyLength = 32
    scheme               = "https"
)

// UserInfo carries information about long term users.
type UserInfo struct {
    AccessKeyID     string               `json:"accessKeyId,omitempty"`
    SecretAccessKey string               `json:"secretAccessKey,omitempty"`
    PolicyName      string               `json:"policyName,omitempty"`
    Status          madmin.AccountStatus `json:"status"`
    CreationTime    time.Time            `json:"creationTime"`
}

func (b *minioBackend) getActiveUserCreds(ctx context.Context, client *madmin.AdminClient, req *logical.Request,
    roleName string, role *Role, now time.Time, maxTtl time.Duration) (*UserInfo, error) {
    var newKeyName string
    if role.UserNamePrefix == "" {
        newKeyName = req.ID
    } else {
        newKeyName = fmt.Sprintf("%s-%s", role.UserNamePrefix, req.ID)
    }

    users, ok := b.userCredsMap[roleName]
    if ok {
        if len(users) == 1 {
            b.Logger().Info("Vault has one oss credential for " + roleName)
            cred1 := users[0]
            if b.isUserCredentialExpired(cred1, maxTtl, now) {
                b.Logger().Info("Credentials expired and hence creating new one")
                cred2, err := b.addUser(ctx, req, client, newKeyName, role, roleName)
                if err != nil {
                    return nil, err
                }
                return cred2, nil
            } else {
                return &cred1, nil
            }
        } else {
            b.Logger().Info("Vault has two oss credentials for " + roleName)
            oldCredential := users[0]
            if users[1].CreationTime.Before(oldCredential.CreationTime) {
                oldCredential = users[1]
            }

            if !b.isUserCredentialExpired(oldCredential, maxTtl, now) {
                return &oldCredential, nil
            }
            cred2, cred3, err := b.removeOldestAndAddNewUserCreds(ctx, req, client, newKeyName, roleName, role)
            if err != nil {
                return nil, err
            }
            if b.isUserCredentialExpired(*cred2, maxTtl, now) {
                b.Logger().Info("Credentials expired and hence returning new one")
                return cred3, nil
            } else {
                return cred2, nil
            }
        }
    }

    b.Logger().Info("Role:", roleName, "is not found in vault!")
    b.Logger().Info("Application requesting for user credentials for the first time")

    userCreds, err := b.addUser(ctx, req, client, newKeyName, role, roleName)
    if err != nil {
        return nil, err
    }
    return userCreds, nil

}

func (b *minioBackend) addUser(ctx context.Context, req *logical.Request, client *madmin.AdminClient, userAccesskey string,
    role *Role, roleName string) (*UserInfo, error) {
    b.userCredsMapMutex.Lock()
    defer b.userCredsMapMutex.Unlock()

    secretAccessKey, err := b.generateSecretAccessKey()
    if err != nil {
        return nil, err
    }
    b.Logger().Info("Adding user to minio")
    err = client.AddUser(ctx, userAccesskey, secretAccessKey)
    if err != nil {
        b.Logger().Error("Adding minio user failed userAccesskey", userAccesskey, "error", err)
        return nil, err
    }

    // Attaching policy to the user
    policyAssociationReq := madmin.PolicyAssociationReq{
        Policies: strings.Split(role.PolicyName, ","),
        User:     userAccesskey,
    }

    _, err = client.AttachPolicy(ctx, policyAssociationReq)
    if err != nil {
        b.Logger().Error("Setting minio user policy failed userAccesskey", userAccesskey,
            "policy", role.PolicyName, "error", err)
        return nil, err
    }

    // Gin up the madmin.UserInfo struct
    userInfo := UserInfo{
        AccessKeyID:     userAccesskey,
        SecretAccessKey: secretAccessKey,
        PolicyName:      role.PolicyName,
        Status:          madmin.AccountEnabled,
        CreationTime:    time.Now(),
    }
    //Update map with userInfo and store it in vault storage
    b.userCredsMap[roleName] = append(b.userCredsMap[roleName], userInfo)

    b.Logger().Info("Updating vault persistence storage with new credentials")
    b.updateVaultStorage(ctx, req)
    return &userInfo, nil
}

func (b *minioBackend) getSTS(ctx context.Context, req *logical.Request, userInfo *UserInfo,
    policy string, ttl int) (cr.Value, error) {

    b.Logger().Info("Getting STS credentials")
    var stsEndpoint string

    config, err := b.GetConfig(ctx, req.Storage)
    if err != nil {
        return cr.Value{}, err
    }
    stsEndpoint = scheme + "://" + config.Endpoint
    var stsOpts cr.STSAssumeRoleOptions
    stsOpts.AccessKey = userInfo.AccessKeyID
    stsOpts.SecretKey = userInfo.SecretAccessKey
    stsOpts.Policy = string(policy)
    stsOpts.DurationSeconds = ttl

    credsObject, err := cr.NewSTSAssumeRole(stsEndpoint, stsOpts)
    if err != nil {
        return cr.Value{}, err
    }

    v, err := credsObject.Get()
    if err != nil {
        return cr.Value{}, err
    }

    return v, nil
}

func (b *minioBackend) removeAllUser(ctx context.Context, req *logical.Request, role *Role, roleName string) error {
    b.userCredsMapMutex.Lock()
    defer b.userCredsMapMutex.Unlock()

    client, err := b.getMadminClient(ctx, req.Storage)
    if err != nil {
        b.Logger().Error("error fetching madmin client!", err)
        return err
    }
    if users, exists := b.userCredsMap[roleName]; exists {
        for _, creds := range users {
            policyAssociationReq := madmin.PolicyAssociationReq{
                Policies: strings.Split(role.PolicyName, ","),
                User:     creds.AccessKeyID,
            }
            _, err = client.DetachPolicy(ctx, policyAssociationReq)
            if err != nil {
                b.Logger().Error("Error in detaching policy for ", roleName, "accessKey", creds.AccessKeyID)
                return err
            }
            if err = client.RemoveUser(ctx, creds.AccessKeyID); err != nil {
                b.Logger().Error("Error in removing user for ", roleName, "accessKey", creds.AccessKeyID)
                return err
            }
        }
        delete(b.userCredsMap, roleName)
        b.Logger().Info("Updating vault persistent storage after removing all user credentials")
        b.updateVaultStorage(ctx, req)
    } else {
        b.Logger().Info(roleName + " does not exist in vault")
    }
    return nil
}

func (b *minioBackend) generateSecretAccessKey() (string, error) {
    b.Logger().Info("Generating secrect access key for user")
    randBytes, err := uuid.GenerateRandomBytes(minioSecretKeyLength)

    if err != nil {
        return "", fmt.Errorf("error generating random bytes: %v", err)
    }

    return base64.StdEncoding.EncodeToString(randBytes), nil
}

func (b *minioBackend) removeOldestUserCreds(ctx context.Context, req *logical.Request, client *madmin.AdminClient, roleName string, role *Role) error {
    b.userCredsMapMutex.Lock()
    defer b.userCredsMapMutex.Unlock()

    users := b.userCredsMap[roleName]
    oldCredential := users[0]
    if len(users) > 1 {
        if users[1].CreationTime.Before(oldCredential.CreationTime) {
            oldCredential = users[1]
        }
    }

    policyAssociationReq := madmin.PolicyAssociationReq{
        Policies: strings.Split(role.PolicyName, ","),
        User:     oldCredential.AccessKeyID,
    }
    _, err := client.DetachPolicy(ctx, policyAssociationReq)
    if err != nil {
        b.Logger().Error("Error in detaching policy for ", roleName, "accessKey", oldCredential.AccessKeyID)
        return err
    }
    if err = client.RemoveUser(ctx, oldCredential.AccessKeyID); err != nil {
        b.Logger().Error("Error in removing user for ", roleName, "accessKey", oldCredential.AccessKeyID)
        return err
    }

    b.Logger().Info("Removing oldest credentials from vault")
    if len(users) == 1 {
        delete(b.userCredsMap, roleName)
    } else {
        if users[0].AccessKeyID == oldCredential.AccessKeyID && users[0].SecretAccessKey == oldCredential.SecretAccessKey {
            b.userCredsMap[roleName] = users[1:] //Remove first element
        } else {
            b.userCredsMap[roleName] = users[:1] //Remove second element
        }
    }

    b.Logger().Info("Updating vault persistent storage after removing oldest user credentials")
    b.updateVaultStorage(ctx, req)
    return nil
}

func (b *minioBackend) removeOldestAndAddNewUserCreds(ctx context.Context, req *logical.Request,
    client *madmin.AdminClient, newUserAccesskey string, roleName string,
    role *Role) (*UserInfo, *UserInfo, error) {

    b.userCredsMapMutex.Lock()
    defer b.userCredsMapMutex.Unlock()

    b.Logger().Info("Deleting oldest expired credentials from minio for " + roleName)
    users := b.userCredsMap[roleName]
    oldCredential := users[0]
    if users[1].CreationTime.Before(oldCredential.CreationTime) {
        oldCredential = users[1]
    }

    policyAssociationReq := madmin.PolicyAssociationReq{
        Policies: strings.Split(role.PolicyName, ","),
        User:     oldCredential.AccessKeyID,
    }
    _, err := client.DetachPolicy(ctx, policyAssociationReq)
    if err != nil {
        b.Logger().Error("Error in detaching policy for ", roleName, "accessKey", oldCredential.AccessKeyID)
        return nil, nil, err
    }
    if err = client.RemoveUser(ctx, oldCredential.AccessKeyID); err != nil {
        b.Logger().Error("Error in removing user for ", roleName, "accessKey", oldCredential.AccessKeyID)
        return nil, nil, err
    }

    b.Logger().Info("Removing oldest expired credentials from vault")
    if users[0].AccessKeyID == oldCredential.AccessKeyID && users[0].SecretAccessKey == oldCredential.SecretAccessKey {
        b.userCredsMap[roleName] = users[1:] //Remove first element
    } else {
        b.userCredsMap[roleName] = users[:1] //Remove second element
    }

    cred2 := b.userCredsMap[roleName][0]

    secretAccessKey, err := b.generateSecretAccessKey()
    if err != nil {
        return nil, nil, err
    }
    b.Logger().Info("Adding new user credentials to minio for " + roleName)
    err = client.AddUser(ctx, newUserAccesskey, secretAccessKey)
    if err != nil {
        b.Logger().Error("Adding minio user failed userAccesskey", newUserAccesskey, "error", err)
        return nil, nil, err
    }

    // Attaching policy to the user
    policyAssociationReq = madmin.PolicyAssociationReq{
        Policies: strings.Split(role.PolicyName, ","),
        User:     newUserAccesskey,
    }

    _, err = client.AttachPolicy(ctx, policyAssociationReq)
    if err != nil {
        b.Logger().Error("Setting minio user policy failed userAccesskey", newUserAccesskey,
            "policy", role.PolicyName, "error", err)
        return nil, nil, err
    }

    // Gin up the madmin.UserInfo struct
    cred3 := UserInfo{
        AccessKeyID:     newUserAccesskey,
        SecretAccessKey: secretAccessKey,
        PolicyName:      role.PolicyName,
        Status:          madmin.AccountEnabled,
        CreationTime:    time.Now(),
    }
    //Update map with userInfo and store it in vault storage
    b.userCredsMap[roleName] = append(b.userCredsMap[roleName], cred3)

    b.Logger().Info("Updating vault persistent storage")
    b.updateVaultStorage(ctx, req)
    return &cred2, &cred3, nil
}

func (b *minioBackend) updateVaultStorage(ctx context.Context, req *logical.Request) error {
    entry, err := logical.StorageEntryJSON(userStoragePath, &b.userCredsMap)
    if err != nil {
        b.Logger().Info("Failed to generate JSON configuration when persisting user credentials map to vault")
        return fmt.Errorf("failed to generate JSON configuration persisting user credentials map to vault: %v", err)
    }

    if err := req.Storage.Put(ctx, entry); err != nil {
        b.Logger().Info("failed to persist user credentials map in persistent storage")
        return fmt.Errorf("failed to persist user credentials map in persistent storage: %v", err)
    }

    b.Logger().Info("Vault persistent storage updated successfully!")

    return nil
}

func (b *minioBackend) isUserCredentialExpired(creds UserInfo, maxTtl time.Duration, now time.Time) bool {
    elapsed := now.Sub(creds.CreationTime)
    return elapsed >= maxTtl
}

// Setter function only for unit tests
func (b *minioBackend) SetuserCredsMap(newMap map[string][]UserInfo) {
    b.userCredsMap = newMap
}
