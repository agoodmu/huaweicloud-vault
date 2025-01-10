package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
)

const pathCredentialsHelpSyn = `
Generate a HashiCups API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a HashiCups API user tokens
based on a particular role. A role can only represent a user token,
since HashiCups doesn't have other types of tokens.
`

func pathCredentials(b *hwcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathTempCredentialsRead,
			},
			ExistenceCheck:  b.pathExistenceCheck,
			HelpSynopsis:    pathCredentialsHelpSyn,
			HelpDescription: pathCredentialsHelpDesc,
		},
	}
}

func (b *hwcBackend) pathTempCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var roleEntry *hwcTempRoleEntry
	roleName := d.Get("name").(string)
	roledata, err := req.Storage.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role %s: %w", req.Path, err)
	}
	if roledata == nil {
		return nil, fmt.Errorf("role %s does not contain necessary data", roleName)
	}
	err = roledata.DecodeJSON(&roleEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode role data: %s", err.Error())
	}

	client, err := b.getClient(ctx, req.Storage, "role/"+roleName)
	if err != nil {
		return logical.ErrorResponse("failed to get backend client: %s", err.Error()), err
	}

	targetAgencyName := roleEntry.AgencyName
	targetAccountName := roleEntry.AccountName
	tokenTTL := int32(roleEntry.TTL.Seconds())
	result, err := client.CreateTemporaryAccessKeyByAgency(&model.CreateTemporaryAccessKeyByAgencyRequest{
		Body: &model.CreateTemporaryAccessKeyByAgencyRequestBody{
			Auth: &model.AgencyAuth{
				Identity: &model.AgencyAuthIdentity{
					Methods: []model.AgencyAuthIdentityMethods{model.GetAgencyAuthIdentityMethodsEnum().ASSUME_ROLE},
					AssumeRole: &model.IdentityAssumerole{
						AgencyName:      targetAgencyName,
						DomainName:      &targetAccountName,
						DurationSeconds: &tokenTTL,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	expireTime, err := time.Parse(time.RFC3339Nano, result.Credential.ExpiresAt)
	if err != nil {
		return nil, err
	}
	localExpireTime := expireTime.In(time.Local)
	resp := b.Secret(TokenType).Response(map[string]interface{}{
		"access_key":     result.Credential.Access,
		"secret_key":     result.Credential.Secret,
		"security_token": result.Credential.Securitytoken,
		"expire_time":    localExpireTime,
	}, nil)

	return resp, nil
}
