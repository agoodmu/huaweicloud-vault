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

type hwcAKSKEntry struct {
	Name         string        `json:"name"`
	AccessKey    string        `json:"access_key"`
	SecretKey    string        `json:"secret_key"`
	AccountID    string        `json:"account_id"`
	UserID       string        `json:"user_id"`
	CreationTime string        `json:"creation_time"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
}

func (b *hwcBackend) pathStaticAKSKWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleEntry := new(hwcStaticAKSKRoleEntry)
	config := new(hwcConfig)
	name := d.Get("name").(string)
	roledata, err := req.Storage.Get(ctx, "role/static/"+name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role %s: %w", req.Path, err)
	}
	if roledata == nil {
		return nil, fmt.Errorf("role %s does not contain necessary data", name)
	}
	err = roledata.DecodeJSON(&roleEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode role data: %s", err.Error())
	}

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
				Name: name,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user group %s", err.Error())
	}

	userResult, err := newClient.KeystoneCreateUser(&model.KeystoneCreateUserRequest{
		Body: &model.KeystoneCreateUserRequestBody{
			User: &model.KeystoneCreateUserOption{
				Name:        name,
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

	domainInfo, err := newClient.KeystoneListAuthDomains(&model.KeystoneListAuthDomainsRequest{})
	domains := make([]string, 1)
	for _, domain := range *domainInfo.Domains {
		domains = append(domains, domain.Id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain id: %s", err.Error())
	}

	for _, roleId := range roleIds {
		_, err := newClient.UpdateDomainGroupInheritRole(&model.UpdateDomainGroupInheritRoleRequest{
			DomainId: domains[0],
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
	err = b.writeDataToPath(ctx, req, map[string]interface{}{
		"name":          name,
		"access_key":    akskResult.Credential.Access,
		"secret_key":    akskResult.Credential.Secret,
		"user_id":       akskResult.Credential.UserId,
		"creation_time": akskResult.Credential.CreateTime,
		"account_id":    domains[0],
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store the credentials: %s", err.Error())
	}
	return nil, nil
}

func (b *hwcBackend) pathStaticAKSKRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	akskEntry := new(hwcAKSKEntry)
	entryData, err := b.readDataFromPath(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read data at %s: %s", req.Path, err.Error())
	}
	if entryData == nil {
		return nil, fmt.Errorf("path %s does not contain any data", req.Path)
	}
	err = entryData.DecodeJSON(akskEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %s", err.Error())
	}
	return b.Secret(StaticAKSK).Response(map[string]interface{}{
		"name":       akskEntry.Name,
		"access_key": akskEntry.AccessKey,
		"secret_key": akskEntry.SecretKey,
	}, nil), nil
}
