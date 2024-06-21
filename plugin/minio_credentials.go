package minio

import (
    "context"
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
    ExpirationDate  time.Time            `json:"expirationDate"`
}

func (b *minioBackend) getActiveUserCreds(ctx context.Context, req *logical.Request, roleName string, role *Role, now time.Time) (*UserInfo, error) {
    userCredsMap, err := b.getAllUserCreds(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    var newKeyName string
    if role.UserNamePrefix == "" {
        newKeyName = req.ID
    } else {
        newKeyName = fmt.Sprintf("%s-%s", role.UserNamePrefix, req.ID)
    }

    users, ok := userCredsMap[roleName]
    if ok {
        if len(users) == 1 {
            userCreds := users[0]
            if b.isUserCredentialExpired(ctx, now, userCreds) {
                newUserCreds, err := b.addUser(ctx, req, newKeyName, role, roleName, now)
                if err != nil {
                    return nil, err
                }
                return newUserCreds, nil 
            } else {
                return &userCreds, nil
            }
        } else {
            oldestCreds, err := b.getOldestUserCreds(ctx, req, roleName)
            if err != nil {
                return nil, err
            }
            err = b.removeUser(ctx, req, role, roleName, oldestCreds)
            if err != nil {
                return nil, err
            }
            userCredsMap, err = b.getAllUserCreds(ctx, req.Storage)
            if err != nil {
                return nil, err
            }
            userCreds := userCredsMap[roleName][0]
            newUserCreds, err := b.addUser(ctx, req, newKeyName, role, roleName, now)
            if err != nil {
                return nil, err
            }
            if b.isUserCredentialExpired(ctx, now, userCreds) {
                return newUserCreds, nil
            } else {
                return &userCreds, nil
            }
        }
    }

    b.Logger().Info("This roleName", roleName, "is not found in vault!")
    b.Logger().Info("Application requesting for user credentials for the first time")

    userCreds, err := b.addUser(ctx, req, newKeyName, role, roleName, now)
    if err != nil {
        return nil, err
    }
    return userCreds, nil

}

func (b *minioBackend) addUser(ctx context.Context, req *logical.Request, userAccesskey string,
    role *Role, roleName string, now time.Time) (*UserInfo, error) {
    b.Logger().Info("Adding user by madmin client and persisting it inside local storage")

    client, err := b.getMadminClient(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    secretAccessKey, err := b.generateSecretAccessKey()
    if err != nil {
        return nil, err
    }

    err = client.AddUser(ctx, userAccesskey, secretAccessKey)
    if err != nil {
        b.Logger().Error("Adding minio user failed", "userAccesskey", userAccesskey, "error", err)
        return nil, err
    }

    // Attaching policy to the user
    policyAssociationReq := madmin.PolicyAssociationReq{
        Policies: []string{role.PolicyName},
        User: userAccesskey,
    }

    _, err = client.AttachPolicy(ctx, policyAssociationReq)
    if err != nil {
        b.Logger().Error("Setting minio user policy failed", "minoUserAccesskey", userAccesskey,
            "policy", role.PolicyName, "error", err)
        return nil, err
    }

    maxTtl := int(role.MaxTTL.Seconds() / 86400)
    
    // Gin up the madmin.UserInfo struct
    userInfo := UserInfo{
        AccessKeyID:     userAccesskey,
        SecretAccessKey: secretAccessKey,
        PolicyName:      role.PolicyName,
        Status:          madmin.AccountEnabled,
        ExpirationDate:  now.AddDate(0, 0, maxTtl),
    }
    //Update map with userInfo and store it in vault storage
    userMap, err := b.getAllUserCreds(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    userMap[roleName] = append(userMap[roleName], userInfo)

    b.updateVaultStorage(ctx, req, userMap)

    // Destroy any old client which may exist so we get a new one
    // with the next request
    b.invalidateMadminClient()

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

func (b *minioBackend) removeUser(ctx context.Context, req *logical.Request, role *Role, roleName string, oldestCreds *UserInfo) error {
    b.Logger().Info("Removing user by madmin client")
    client, err := b.getMadminClient(ctx, req.Storage)
    if err != nil {
        return fmt.Errorf("failed to receive madmin client: %v", err)
    }
    policyAssociationReq := madmin.PolicyAssociationReq{
        Policies: []string{role.PolicyName},
        User: oldestCreds.AccessKeyID,
    }
    _, err = client.DetachPolicy(ctx, policyAssociationReq)
    if err != nil {
        return fmt.Errorf("failed to detach policy by madmin client: %v", err)
    }
    if err = client.RemoveUser(ctx, oldestCreds.AccessKeyID); err != nil {
        return fmt.Errorf("failed to delete user access by madmin: %v", err)
    }

    b.Logger().Info("Removing oldest credentials from vault and updating persistent storage")
    userMap, err := b.getAllUserCreds(ctx, req.Storage)
    if err != nil {
        return err
    }
    if users, exists := userMap[roleName]; exists {
        if len(users) == 1 {
            delete(userMap, roleName)
        } else {
            //Iterate over users and find userInfo to delete
            for i, userCred := range users {
                if userCred.AccessKeyID == oldestCreds.AccessKeyID && userCred.SecretAccessKey == oldestCreds.SecretAccessKey {
                    userMap[roleName] = append(users[:i], users[i + 1:]...)
                }
            }
        }
    }

    b.updateVaultStorage(ctx, req, userMap)
    b.invalidateMadminClient()
    return nil
}

func (b *minioBackend) removeAllUser(ctx context.Context, req *logical.Request, role *Role, roleName string) (error) {
    userCredsMap, err := b.getAllUserCreds(ctx, req.Storage)
    if err != nil {
        return err
    }
    if users, exists := userCredsMap[roleName]; exists {
        for _, userCred := range users {
            err = b.removeUser(ctx, req, role, roleName, &userCred)
            if err != nil {
                return err
            }
        }
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

func (b *minioBackend) getAllUserCreds(ctx context.Context, s logical.Storage) (map[string][]UserInfo, error) {
    b.Logger().Info("Retrieving user info stored in persistent storage")

    entry, err := s.Get(ctx, userStoragePath)
    if err != nil {
        return nil, fmt.Errorf("failed to get user entry map from persistent storage: %v", err)
    }

    var userMap = make(map[string][]UserInfo)
    //if there is no credentials created for the role, entry will be nil. Application requesting creds for first time.
    if entry == nil {
        return userMap, nil
    }

    if err := entry.DecodeJSON(&userMap); err != nil {
        return nil, fmt.Errorf("failed to decode user entry map: %v", err)
    }

    return userMap, nil
}

func (b *minioBackend) getOldestUserCreds(ctx context.Context, req *logical.Request, roleName string) (*UserInfo, error) {
    userInfoMap, err := b.getAllUserCreds(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    users := userInfoMap[roleName]
    oldCredential := users[0]    
    for i := 1; i < len(users); i++ {
        if users[i].ExpirationDate.Before(oldCredential.ExpirationDate) {
            oldCredential = users[i]
        }
    }

    return &oldCredential, nil
}

func (b *minioBackend) isUserCredentialExpired(ctx context.Context, now time.Time, userInfo UserInfo) (bool) {
    return now.After(userInfo.ExpirationDate)
}

func (b *minioBackend) updateVaultStorage(ctx context.Context, req *logical.Request, userMap map[string][]UserInfo) error {
    entry, err := logical.StorageEntryJSON(userStoragePath, userMap)
    if err != nil {
        return fmt.Errorf("failed to generate JSON configuration when adding user details: %v", err)
    }

    if err := req.Storage.Put(ctx, entry); err != nil {
        return fmt.Errorf("failed to persist user in persistent storage: %v", err)
    }

    return nil
}