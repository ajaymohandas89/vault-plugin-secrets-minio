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
        Pattern: "(creds|sts)/" + framework.GenericNameRegex("role"),
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

    role, err := b.GetRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, fmt.Errorf("error fetching role: %v", err)
    }

    userCreds, err := b.getActiveUserCreds(ctx, req, roleName, role, now)
    if err != nil {
        return nil, err
    }

    credentialType := role.CredentialType
    var resp map[string]interface{}

    switch credentialType {
    case StaticCredentialType:
        resp = map[string]interface{}{
            "accessKeyId":     		userCreds.AccessKeyID,
            "secretAccessKey": 		userCreds.SecretAccessKey,
            "policy_name":     		role.PolicyName,
            "ttl":             		userCreds.ExpirationDate.Format(time.DateTime),
            "userAccountStatus": 	userCreds.Status,
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
            "sessionToken":	   newKey.SessionToken,
            "ttl":             newKey.Expiration.Format(time.DateTime),
        }
    }
    

    return &logical.Response{
        Data: resp,
    }, nil
}

func (b *minioBackend) pathKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    roleName := d.Get("role").(string)
    r, err := b.GetRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, err
    }
    oldestCreds, err := b.getOldestUserCreds(ctx, req, roleName)
    if err != nil {
        return nil, err
    }
    err = b.removeUser(ctx, req, r, roleName, oldestCreds)
    if err != nil {
        return nil, err
    }
    return nil, nil
}