package minio

import (
	"context"
	"fmt"
	"strings"
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
				Type:        framework.TypeString,
				Default:     "1h",
				Description: "Default lifetime of the returned sts credentials",
			},
			"policy_name": {
				Type:        framework.TypeString,
				Description: "Generate STS credentials for a specific policy",
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
		b.Logger().Error("Invalid max ttl set for ", roleName, err)
		return nil, err
	}

	gracePeriod, err := time.ParseDuration(role.GracePeriod)
	if err != nil {
		b.Logger().Error("Invalid grace period set for ", roleName, err)
		return nil, err
	}

	// resolveOrCreateCred handles full lifecycle: create, evict, retire
	// of minio user credentials for this role
	activeCred, err := b.resolveOrCreateCred(ctx, client, req, roleName, role, now, maxTtl, gracePeriod)
	if err != nil {
		b.Logger().Error("error fetching user credentials for", roleName, err)
		return nil, err
	}

	elapsed := now.Sub(activeCred.CreationTime)
	remainingTtl := (maxTtl - elapsed).Truncate(time.Second)

	credentialType := role.CredentialType
	var resp map[string]interface{}

	switch credentialType {
	case StaticCredentialType:
		resp = map[string]interface{}{
			"accessKeyId":       activeCred.AccessKeyID,
			"secretAccessKey":   activeCred.SecretAccessKey,
			"policy_name":       role.PolicyName,
			"ttl":               remainingTtl.String(),
			"userAccountStatus": activeCred.Status,
		}
	case StsCredentialType:
		// InfoCannedPolicy accepts a single policy name, so the application must
		// send exactly one policy and it has to be one of the comma separated
		// policies configured on the role.
		stsPolicyName := strings.TrimSpace(d.Get("policy_name").(string))
		if stsPolicyName == "" {
			b.Logger().Error("policy name is required to create STS credentials for role", roleName,
				"rolePolicies", role.PolicyName)
			return nil, fmt.Errorf("policy name is required to create STS credentials for role %s, allowed policies: %s",
				roleName, role.PolicyName)
		}

		policyAllowed := false
		for _, rolePolicy := range strings.Split(role.PolicyName, ",") {
			if strings.TrimSpace(rolePolicy) == stsPolicyName {
				policyAllowed = true
				break
			}
		}
		if !policyAllowed {
			b.Logger().Error("policy requested by client is not configured on role", roleName,
				"policy", stsPolicyName, "rolePolicies", role.PolicyName)
			return nil, fmt.Errorf("STS token cannot be created: policy %q is not allowed for role %s, allowed policies: %s",
				stsPolicyName, roleName, role.PolicyName)
		}

		reqTtlStr := d.Get("ttl").(string)
		reqTtlDuration, err := time.ParseDuration(reqTtlStr)
		if err != nil {
			b.Logger().Error("STS token cannot be created: Invalid STS ttl set by client ", roleName, err)
			return nil, err
		}
		maxStsTTLDuration, err := time.ParseDuration(role.MaxStsTTL)
		if err != nil {
			b.Logger().Error("STS token cannot be created: Invalid Max STS ttl ", err)
			return nil, err
		}
		requestedTtl := int(reqTtlDuration.Seconds())
		maxStsTtl := int(maxStsTTLDuration.Seconds())

		if requestedTtl > 0 && requestedTtl < maxStsTtl {
			maxStsTtl = requestedTtl
		}

		b.Logger().Info("fetching policy " + stsPolicyName + " from minio for STS credentials")
		policyInfo, err := client.InfoCannedPolicy(ctx, stsPolicyName)
		if err != nil {
			b.Logger().Error("STS token cannot be created: failed to fetch policy from minio for role", roleName, "policy", stsPolicyName, "error", err)
			return nil, err
		}

		stsKey, err := b.getSTS(ctx, client, activeCred, string(policyInfo.Policy), maxStsTtl)
		if err != nil {
			return nil, err
		}
		resp = map[string]interface{}{
			"accessKeyId":     stsKey.AccessKeyID,
			"secretAccessKey": stsKey.SecretAccessKey,
			"sessionToken":    stsKey.SessionToken,
			"ttl":             time.Until(stsKey.Expiration).Round(time.Second).String(),
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
	err = b.revokeActiveCreds(ctx, req, client, roleName, r)
	if err != nil {
		b.Logger().Error("error in revoking oldest credentials", err)
		return nil, err
	}
	return nil, nil
}
