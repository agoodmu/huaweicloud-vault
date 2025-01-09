package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
)

const pathCredentialsHelpSyn = `
Generate a HashiCups API token from a specific Vault role.
`

type hwcTempCredentials struct {
	AccessKey     string    `json:"access_key"`
	SecretKey     string    `json:"secret_key"`
	SecurityToken string    `json:"security_token"`
	ExpireTime    time.Time `json:"expire_time"`
}

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
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathCredentialsHelpSyn,
			HelpDescription: pathCredentialsHelpDesc,
		},
	}
}

func (b *hwcBackend) pathTempCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var roleEntry *hwcTempRoleEntry
	var credentials *hwcTempCredentials
	roleName := d.Get("name").(string)
	roledata, err := req.Storage.Get(ctx, "role/"+roleName)
	if err != nil {
		return logical.ErrorResponse("failed to get data for role %s", roleName), fmt.Errorf("error retrieving role: %w", err)
	}
	err = roledata.DecodeJSON(&roleEntry)
	if err != nil {
		return logical.ErrorResponse("failed to decode role data: %s", err.Error()), err
	}

	if roleEntry == nil {
		return logical.ErrorResponse("role %s does not contain necessary data"), errors.New("error retrieving role: role is nil")
	}
	credsData, err := b.readDataFromPath(ctx, req)
	if err != nil {
		return logical.ErrorResponse("failed to read path %s: %s", req.Path, err.Error()), err
	}
	err = credsData.DecodeJSON(&credentials)
	if err != nil {
		return logical.ErrorResponse("failed to decode credential data: %s", err.Error()), err
	}
	if credentials != nil && credentials.ExpireTime.Before(time.Now().Add(roleEntry.MinimumDuration)) {
		return b.Secret(TokenType).Response(map[string]interface{}{
			"access_key":     credentials.AccessKey,
			"secret_key":     credentials.SecretKey,
			"security_token": credentials.SecurityToken,
			"expire_time":    credentials.ExpireTime,
		}, nil), nil
	}
	client, err := b.getClient(ctx, req.Storage)
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
	}, map[string]interface{}{
		"access_key":     result.Credential.Access,
		"secret_key":     result.Credential.Secret,
		"security_token": result.Credential.Securitytoken,
		"expire_time":    localExpireTime,
	},
	)

	return resp, nil
}
