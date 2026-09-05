package minio

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/minio/madmin-go/v4"
	cr "github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	userStoragePath      = "users"
	minioSecretKeyLength = 32
	scheme               = "https"
	maxCredsPerRole      = 2
)

// UserInfo carries information about long term users.
type UserInfo struct {
	AccessKeyID     string               `json:"accessKeyId,omitempty"`
	SecretAccessKey string               `json:"secretAccessKey,omitempty"`
	PolicyName      string               `json:"policyName,omitempty"`
	Status          madmin.AccountStatus `json:"status"`
	CreationTime    time.Time            `json:"creationTime"`

	/* ExpiredAt is nil while the credential is active
	   It is set to the time of retirement when credential exceeds maxTTL
	   or is manually revoked
	*/
	ExpiredAt *time.Time `json:"expiredAt"`
}

func (b *minioBackend) resolveOrCreateCred(
	ctx context.Context,
	client *madmin.AdminClient,
	req *logical.Request,
	roleName string,
	role *Role,
	now time.Time,
	maxTtl time.Duration,
	gracePeriod time.Duration) (*UserInfo, error) {

	b.userCredsMapMutex.Lock()
	defer b.userCredsMapMutex.Unlock()

	// evictionDeadline is max age after which a credentials must be deleted from vault and MinIO
	evictionDeadline := maxTtl + gracePeriod

	creds := b.userCredsMap[roleName]
	stateChanged := false // set to true whenever in-memory state changes

	// reuse memory but start with empty slice
	retainedCreds := creds[:0]

	/*
	   Phase 1: Evict credentials past (Max TTL + Grace Period)
	   Drop any credentials whose age has exceeded eviction deadline
	   Reuse the backing array creds[:0] to avoid an allocation
	*/
	for i := range creds {
		c := &creds[i]
		credAge := now.Sub(c.CreationTime)
		if c.isEvictable(evictionDeadline, credAge) {
			b.Logger().Info("evicting credential past Max TTL & grace period",
				"role", roleName,
				"accessKey", c.AccessKeyID)
			b.deleteCredsFromMinio(ctx, client, roleName, role, *c)
			stateChanged = true
			continue
		}
		retainedCreds = append(retainedCreds, *c)
	}
	creds = retainedCreds

	/*
	   Phase 2: Retire credentials that exceeds Max TTL
	   These credentials remain in MinIO and Vault storage throughout the grace period
	   so services can still authenticate with old keys
	   ExpiredAt is stamped here for observability only and not used for evicting
	*/
	var activeCred *UserInfo
	for i := range creds {
		c := &creds[i]
		if c.ExpiredAt != nil {
			continue // Already retired on previous request
		}
		credAge := now.Sub(c.CreationTime)
		if credAge >= maxTtl {
			t := now
			c.ExpiredAt = &t
			b.Logger().Info("credential has exceeded Max TTL",
				"role", roleName,
				"accessKey", c.AccessKeyID,
				"ttl", (evictionDeadline - credAge).Truncate(time.Second))
			stateChanged = true
		} else {
			// Credential is still within Max TTL - this is our active credential
			// Only one active credential can exist given max 2 creds invariant
			activeCred = c
		}
	}

	b.userCredsMap[roleName] = creds

	// Phase 3: Issue existing active credential or create new one
	if activeCred != nil {
		// active credential exists with Max TTL
		// if phase 1 or 2 mutated state, persist those changes before returning
		// executed only when we are returning an existing credential
		if stateChanged {
			if err := b.updateUserCredsInVaultStorage(ctx, req); err != nil {
				return nil, err
			}
		}
		return activeCred, nil
	}

	/*
	   No active credential found, either first request for this role or
	   previous credential just passed Max TTL. Create new one
	   Before creating, enforce max 2 creds per role contraint
	   Vault Persistent storage holds at most [cred1(retired), cred2(active)]
	*/
	if len(creds) >= maxCredsPerRole {
		oldestIdx := b.findOldestRetiredCredIdx(creds)
		if oldestIdx != -1 {
			b.Logger().Warn("role", roleName, "can only store max 2 credentials in vault, evicting oldest retired credentials",
				"accessKey", creds[oldestIdx].AccessKeyID)

			b.deleteCredsFromMinio(ctx, client, roleName, role, creds[oldestIdx])
			creds = append(creds[:oldestIdx], creds[oldestIdx+1:]...)
			b.userCredsMap[roleName] = creds
		}
	}

	var newKeyName string
	if role.UserNamePrefix == "" {
		newKeyName = req.ID
	} else {
		newKeyName = fmt.Sprintf("%s-%s", role.UserNamePrefix, req.ID)
	}

	newCred, err := b.createAndStoreNewCred(ctx, req, client, newKeyName, role, roleName)
	if err != nil {
		return nil, err
	}

	return newCred, nil
}

func (b *minioBackend) createAndStoreNewCred(ctx context.Context, req *logical.Request, client *madmin.AdminClient, userAccesskey string,
	role *Role, roleName string) (*UserInfo, error) {
	secretAccessKey, err := b.generateSecretAccessKey()
	if err != nil {
		return nil, err
	}
	b.Logger().Info("Adding user in minio for role " + roleName)
	err = client.AddUser(ctx, userAccesskey, secretAccessKey)
	if err != nil {
		b.Logger().Error("Adding minio user failed accessKey "+userAccesskey, "error", err)
		return nil, err
	}

	// Attaching policy to the user
	policyAssociationReq := madmin.PolicyAssociationReq{
		Policies: strings.Split(role.PolicyName, ","),
		User:     userAccesskey,
	}

	_, err = client.AttachPolicy(ctx, policyAssociationReq)
	if err != nil {
		b.Logger().Error("Setting minio user policy failed for accessKey" + userAccesskey +
			"policy " + role.PolicyName)
		if removeErr := client.RemoveUser(ctx, userAccesskey); removeErr != nil {
			b.Logger().Error("failed to clean up MinIO user after policy attach failure, accesskey", userAccesskey, "error", removeErr)
			if disableErr := client.SetUserStatus(ctx, userAccesskey, madmin.AccountDisabled); disableErr != nil {
				b.Logger().Error("failed to disable user for role ", roleName+" accessKey", userAccesskey, "error", disableErr)
			}
		}
		return nil, err
	}

	b.Logger().Info("Successfully added user to minio and attached oss policy!")

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
	if err := b.updateUserCredsInVaultStorage(ctx, req); err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func (b *minioBackend) generateSecretAccessKey() (string, error) {
	b.Logger().Info("Generating secrect access key for user")
	randBytes, err := uuid.GenerateRandomBytes(minioSecretKeyLength)

	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %v", err)
	}

	return base64.StdEncoding.EncodeToString(randBytes), nil
}

func (b *minioBackend) findOldestRetiredCredIdx(creds []UserInfo) int {
	oldest := -1
	for i := range creds {
		if creds[i].ExpiredAt == nil {
			continue // active credential - not a candidate
		}
		if oldest == -1 || creds[i].ExpiredAt.Before(*creds[oldest].ExpiredAt) {
			oldest = i
		}
	}
	return oldest
}

func (b *minioBackend) removeAllUserCreds(ctx context.Context, req *logical.Request, role *Role, roleName string) error {
	b.userCredsMapMutex.Lock()
	defer b.userCredsMapMutex.Unlock()

	client, err := b.getMadminClient(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("error fetching madmin client!", err)
		return err
	}

	// Delete every credential (active or retired) if role is deleted
	for _, cred := range b.userCredsMap[roleName] {
		b.deleteCredsFromMinio(ctx, client, roleName, role, cred)
	}
	delete(b.userCredsMap, roleName)

	return b.updateUserCredsInVaultStorage(ctx, req)
}

func (b *minioBackend) revokeActiveCreds(ctx context.Context, req *logical.Request, client *madmin.AdminClient, roleName string, role *Role) error {
	b.userCredsMapMutex.Lock()
	defer b.userCredsMapMutex.Unlock()

	now := time.Now()

	maxTtl, err := time.ParseDuration(role.MaxTTL)
	if err != nil {
		b.Logger().Error("Invalid max ttl set for ", roleName, err)
		return err
	}

	gracePeriod, err := time.ParseDuration(role.GracePeriod)
	if err != nil {
		b.Logger().Error("Invalid grace period set for ", roleName, err)
		return err
	}

	evictionDeadline := maxTtl + gracePeriod
	creds := b.userCredsMap[roleName]

	if len(creds) == 0 {
		b.Logger().Info("no credentials found to remove, role", roleName)
		return nil
	}

	oldexActiveIdx := -1
	for i := range creds {
		if creds[i].ExpiredAt != nil {
			continue // already expired, manual delete means we are force-rotating active credentials
		}
		if oldexActiveIdx == -1 || creds[i].CreationTime.Before(creds[oldexActiveIdx].CreationTime) {
			oldexActiveIdx = i
		}
	}

	if oldexActiveIdx != -1 {
		b.Logger().Info("manually retired credentials, role", roleName, "accessKey", creds[oldexActiveIdx].AccessKeyID)

		b.deleteCredsFromMinio(ctx, client, roleName, role, creds[oldexActiveIdx])
		creds = append(creds[:oldexActiveIdx], creds[oldexActiveIdx+1:]...)
		b.userCredsMap[roleName] = creds
	} else {
		b.Logger().Info("no active credentials found to retire, role", roleName)
	}

	retainedCreds := creds[:0]
	for i := range creds {
		c := &creds[i]
		credAge := now.Sub(c.CreationTime)
		if c.isEvictable(evictionDeadline, credAge) {
			b.Logger().Info("evicting credential past max ttl and grace period during manual deletion, role",
				roleName,
				"accessKey", c.AccessKeyID)
			b.deleteCredsFromMinio(ctx, client, roleName, role, *c)
			continue
		}
		retainedCreds = append(retainedCreds, *c)
	}

	b.userCredsMap[roleName] = retainedCreds
	return b.updateUserCredsInVaultStorage(ctx, req)
}

func (b *minioBackend) deleteCredsFromMinio(ctx context.Context,
	client *madmin.AdminClient, roleName string, role *Role, cred UserInfo) {
	policyAssociationReq := madmin.PolicyAssociationReq{
		Policies: strings.Split(role.PolicyName, ","),
		User:     cred.AccessKeyID,
	}
	_, err := client.DetachPolicy(ctx, policyAssociationReq)
	if err != nil {
		b.Logger().Error("Error in detaching policy for "+roleName+" accessKey "+cred.AccessKeyID, "error", err)
	}
	if err = client.RemoveUser(ctx, cred.AccessKeyID); err != nil {
		b.Logger().Error("Error in removing user for "+roleName+"accessKey "+cred.AccessKeyID, "error", err)
		if disableErr := client.SetUserStatus(ctx, cred.AccessKeyID, madmin.AccountDisabled); disableErr != nil {
			b.Logger().Error("failed to disable user for role ", roleName+" accessKey", cred.AccessKeyID, "error", disableErr)
		}
	}
}

func (b *minioBackend) updateUserCredsInVaultStorage(ctx context.Context, req *logical.Request) error {
	entry, err := logical.StorageEntryJSON(userStoragePath, &b.userCredsMap)
	if err != nil {
		b.Logger().Error("Failed to generate JSON configuration when persisting user credentials map to vault")
		return fmt.Errorf("failed to generate JSON configuration persisting user credentials map to vault: %v", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.Logger().Error("failed to persist user credentials map in persistent storage")
		return fmt.Errorf("failed to persist user credentials map in persistent storage: %v", err)
	}

	b.Logger().Info("Vault persistent storage updated successfully!")

	return nil
}

func (b *minioBackend) getSTS(ctx context.Context, client *madmin.AdminClient, userInfo *UserInfo,
	policy string, ttl int) (cr.Value, error) {

	b.Logger().Info("Getting STS credentials")

	stsEndpoint := client.GetEndpointURL().String()
	var stsOpts cr.STSAssumeRoleOptions
	stsOpts.AccessKey = userInfo.AccessKeyID
	stsOpts.SecretKey = userInfo.SecretAccessKey
	stsOpts.Policy = string(policy)
	stsOpts.DurationSeconds = ttl

	credsObject, err := cr.NewSTSAssumeRole(stsEndpoint, stsOpts)
	if err != nil {
		return cr.Value{}, err
	}

	credCtx := &cr.CredContext{
		Client:   &http.Client{},
		Endpoint: stsEndpoint,
	}

	v, err := credsObject.GetWithContext(credCtx)
	if err != nil {
		return cr.Value{}, err
	}

	return v, nil
}

func (u *UserInfo) isEvictable(evictionDeadline time.Duration, credAge time.Duration) bool {
	return credAge >= evictionDeadline
}

// Setter function only for unit tests
func (b *minioBackend) SetuserCredsMap(newMap map[string][]UserInfo) {
	b.userCredsMap = newMap
}
