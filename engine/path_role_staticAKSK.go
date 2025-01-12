package engine

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	iamregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/region"
)

func (b *hwcBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, ok := d.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get data at %s: %s", req.Path, err.Error())
	}

	if entry == nil {
		return nil, fmt.Errorf("path %s does not exist", req.Path)
	}

	role := new(hwcStaticAKSKRoleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("failed to decode the data from %s: %s", req.Path, err.Error())
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":         role.Name,
			"account_name": role.AccountName,
			"account_id":   role.AccountID,
			"permissions":  role.Permissions,
			"enabled":      role.Enabled,
			"decription":   role.Description,
			"ttl":          role.TTL.Seconds(),
			"max_ttl":      role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *hwcBackend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleEntry := new(hwcStaticAKSKRoleEntry)
	config := new(hwcConfig)
	configData, err := b.readDataFromPath(ctx, req.Storage, "config")
	if err != nil {
		return nil, fmt.Errorf("failed to read backend configuration")
	}

	err = configData.DecodeJSON(config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode configuration data")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get backend client: %s", err.Error())
	}

	name, ok := d.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("missing role name")
	}
	roleEntry.Name = name.(string)
	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	} else {
		return nil, fmt.Errorf("account_name parameter is missing")
	}

	if permissions, ok := d.GetOk("permissions"); ok {
		roleEntry.Permissions = permissions.([]string)
	} else {
		return nil, fmt.Errorf("permissions parameter is missing")
	}

	if descriptions, ok := d.GetOk("description"); ok {
		roleEntry.Description = descriptions.(string)
	} else {
		return nil, fmt.Errorf("the description of the role is missing")
	}

	roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	roleEntry.Enabled = d.Get("enabled").(bool)

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return nil, fmt.Errorf("ttl cannot be greater than max_ttl")
	}

	targetAccountName := roleEntry.AccountName
	result, err := client.CreateTemporaryAccessKeyByAgency(&model.CreateTemporaryAccessKeyByAgencyRequest{
		Body: &model.CreateTemporaryAccessKeyByAgencyRequestBody{
			Auth: &model.AgencyAuth{
				Identity: &model.AgencyAuthIdentity{
					Methods: []model.AgencyAuthIdentityMethods{model.GetAgencyAuthIdentityMethodsEnum().ASSUME_ROLE},
					AssumeRole: &model.IdentityAssumerole{
						AgencyName: config.ManagementAgency,
						DomainName: &targetAccountName,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get temporal credentials for accessing Huawei Cloud: %s", err.Error())
	}
	globalAuth, err := global.NewCredentialsBuilder().WithAk(result.Credential.Access).WithSk(result.Credential.Secret).WithSecurityToken(result.Credential.Securitytoken).SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("failed to creat new auth for target account: %s", err.Error())
	}
	iamRegion, err := iamregion.SafeValueOf(config.Region)
	if err != nil {
		return nil, err
	}
	hcclient, err := iam.IamClientBuilder().WithCredential(globalAuth).WithRegion(iamRegion).SafeBuild()
	if err != nil {
		return nil, err
	}
	newClient := iam.NewIamClient(hcclient)
	groupResult, err := newClient.KeystoneCreateGroup(&model.KeystoneCreateGroupRequest{
		Body: &model.KeystoneCreateGroupRequestBody{
			Group: &model.KeystoneCreateGroupOption{
				Name: name.(string),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user group %s", err.Error())
	}

	userResult, err := newClient.KeystoneCreateUser(&model.KeystoneCreateUserRequest{
		Body: &model.KeystoneCreateUserRequestBody{
			User: &model.KeystoneCreateUserOption{
				Name:        name.(string),
				Enabled:     &roleEntry.Enabled,
				Description: &roleEntry.Description,
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create user %s", err.Error())
	}

	_, err = newClient.KeystoneAddUserToGroup(&model.KeystoneAddUserToGroupRequest{
		GroupId: groupResult.Group.Id,
		UserId:  userResult.User.Id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add user %s to the group", err.Error())
	}
	roleIds := make([]string, 5)
	hwcPolicyResult, err := newClient.KeystoneListPermissions(&model.KeystoneListPermissionsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %s", err.Error())
	}

	for _, policy := range *hwcPolicyResult.Roles {
		if slices.Contains(roleEntry.Permissions, *policy.DisplayName) {
			roleIds = append(roleIds, policy.Id)
		}
	}
	if len(roleIds) == 0 {
		return nil, fmt.Errorf("failed to find the required permission on Huawei Cloud")
	}

	roleEntry.AccountID = globalAuth.DomainId

	b.Logger().Info("Show Info: ", "account_name", roleEntry.Name, "account_id", roleEntry.AccountID, "user_id", userResult.User.Id, "group_id", groupResult.Group.Id)

	for _, roleId := range roleIds {
		_, err := newClient.UpdateDomainGroupInheritRole(&model.UpdateDomainGroupInheritRoleRequest{
			DomainId: roleEntry.AccountID,
			RoleId:   roleId,
			GroupId:  groupResult.Group.Id,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to assign permission to group: %s", err.Error())
		}
	}

	akskResult, err := newClient.CreatePermanentAccessKey(&model.CreatePermanentAccessKeyRequest{
		Body: &model.CreatePermanentAccessKeyRequestBody{
			Credential: &model.CreateCredentialOption{UserId: userResult.User.Id},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ak/sk: %s", err.Error())
	}
	err = b.writeDataToPath(ctx, req.Storage, "creds/static/"+roleEntry.Name, map[string]interface{}{
		"name":          name,
		"access_key":    akskResult.Credential.Access,
		"secret_key":    akskResult.Credential.Secret,
		"user_id":       akskResult.Credential.UserId,
		"creation_time": akskResult.Credential.CreateTime,
		"account_id":    roleEntry.AccountID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store the credentials: %s", err.Error())
	}

	if err := b.writeDataToPath(ctx, req.Storage, req.Path, roleEntry); err != nil {
		return nil, fmt.Errorf("failed to write data to the path %s", req.Path)
	}

	return nil, nil
}

func (b *hwcBackend) pathStaticRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from %s", req.Path)
	}

	if entry == nil {
		return nil, fmt.Errorf("data for path %s is nil", req.Path)
	}

	roleEntry := new(hwcStaticAKSKRoleEntry)

	err = entry.DecodeJSON(&roleEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data %s: %s", req.Path, err.Error())
	}

	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	}

	if permissions, ok := d.GetOk("permissions"); ok {
		roleEntry.Permissions = permissions.([]string)
	}

	if enableRole, ok := d.GetOk("enabled"); ok {
		roleEntry.Enabled = enableRole.(bool)
	}

	if descriptions, ok := d.GetOk("description"); ok {
		roleEntry.Description = descriptions.(string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := b.writeDataToPath(ctx, req.Storage, req.Path, roleEntry); err != nil {
		return nil, fmt.Errorf("failed to write data to the path %s", req.Path)
	}
	return nil, nil
}
