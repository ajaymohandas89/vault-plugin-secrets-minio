package minio

import (
    "context"
    "fmt"
    "time"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func (b *minioBackend) pathKeysRead() *framework.Path {
    return &framework.Path{
        Pattern:      "(creds|sts)/" + framework.GenericNameRegex("role"),
        HelpSynopsis: "Provision a key for this role.",

        Fields: map[string]*framework.FieldSchema{
            "role": {
                Type:        framework.TypeString,
                Description: "Name of role.",
            },
            "ttl": {
                Type:        framework.TypeDurationSecond,
                Default:     "900",
                Description: "Lifetime of the returned sts credentials",
            },
        },

        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ReadOperation: &framework.PathOperation{
                Callback: b.pathKeysCreate,
            },
            logical.DeleteOperation: &framework.PathOperation{
                Callback: b.pathKeysRevoke,
            },
            logical.UpdateOperation: &framework.PathOperation{
                Callback: b.pathKeysCreate,
            },
        },
    }
}

func (b *minioBackend) pathKeysCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    now := time.Now()
    roleName := d.Get("role").(string)

    b.Logger().Info("Retrieving role " + roleName + " details from vault!")
    role, err := b.GetRole(ctx, req.Storage, roleName)
    if err != nil {
        b.Logger().Error("error fetching role!", err)
        return nil, fmt.Errorf("error fetching role: %v", err)
    }

    client, err := b.getMadminClient(ctx, req.Storage)
    if err != nil {
        b.Logger().Error("error fetching madmin client!", err)
        return nil, err
    }

    maxTtl, err := time.ParseDuration(role.MaxTTL)
    if err != nil {
        b.Logger().Error("Invalid Max ttl:", err)
        return nil, err
    }

    userCreds, err := b.getActiveUserCreds(ctx, client, req, roleName, role, now, maxTtl)
    if err != nil {
        b.Logger().Error("error fetching user credentials for", roleName, err)
        return nil, err
    }
    elapsed := now.Sub(userCreds.CreationTime)
    ttl := maxTtl - elapsed
    ttl = ttl.Truncate(time.Second)

    credentialType := role.CredentialType
    var resp map[string]interface{}

    switch credentialType {
    case StaticCredentialType:
        resp = map[string]interface{}{
            "accessKeyId":       userCreds.AccessKeyID,
            "secretAccessKey":   userCreds.SecretAccessKey,
            "policy_name":       role.PolicyName,
            "ttl":               ttl.String(),
            "userAccountStatus": userCreds.Status,
        }
    case StsCredentialType:
        var sts_ttl int
        ttl := int(d.Get("ttl").(int))
        maxTtl := int(role.MaxStsTTL.Seconds())

        if ttl == 0 || ttl > maxTtl {
            sts_ttl = maxTtl
        } else {
            sts_ttl = ttl
        }
        newKey, err := b.getSTS(ctx, req, userCreds, role.PolicyDocument, sts_ttl)
        if err != nil {
            return nil, err
        }
        resp = map[string]interface{}{
            "accessKeyId":     newKey.AccessKeyID,
            "secretAccessKey": newKey.SecretAccessKey,
            "sessionToken":    newKey.SessionToken,
            "ttl":             newKey.Expiration.Format(time.DateTime),
        }
    }

    return &logical.Response{
        Data: resp,
    }, nil
}

func (b *minioBackend) pathKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    roleName := d.Get("role").(string)
    b.Logger().Info("Revoking oldest credentials from vault and minio for ", roleName)
    r, err := b.GetRole(ctx, req.Storage, roleName)
    if err != nil {
        b.Logger().Error("error in getting role", err)
        return nil, err
    }
    client, err := b.getMadminClient(ctx, req.Storage)
    if err != nil {
        b.Logger().Error("error in getting minio admin client", err)
        return nil, err
    }
    err = b.removeOldestUserCreds(ctx, req, client, roleName, r)
    if err != nil {
        b.Logger().Error("error in revoking oldest credentials", err)
        return nil, err
    }
    return nil, nil
}
