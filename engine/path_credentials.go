package engine

import (
	"context"
	"errors"
	"fmt"

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

func pathCredentials(b *hwcBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

func (b *hwcBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *hwcRoleEntry) (*hwcToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}
	b.Logger().Info("Creating token", "agency", roleEntry.Agency)

	var token *hwcToken

	domainName := "hwstaff_intl_sysadmin"
	agencyName := "OrganizationAccountAccessAgency"
	domainDuration := int32(900)
	result, err := client.CreateTemporaryAccessKeyByAgency(&model.CreateTemporaryAccessKeyByAgencyRequest{
		Body: &model.CreateTemporaryAccessKeyByAgencyRequestBody{
			Auth: &model.AgencyAuth{
				Identity: &model.AgencyAuthIdentity{
					Methods: []model.AgencyAuthIdentityMethods{model.GetAgencyAuthIdentityMethodsEnum().ASSUME_ROLE},
					AssumeRole: &model.IdentityAssumerole{
						AgencyName:      agencyName,
						DomainName:      &domainName,
						DurationSeconds: &domainDuration,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	token.AccessKey = result.Credential.Access
	token.SecretKey = result.Credential.Secret
	token.SecurityToken = result.Credential.Securitytoken
	token.ExpireTime = result.Credential.ExpiresAt
	return token, nil
}

func (b *hwcBackend) createUserCreds(ctx context.Context, req *logical.Request, role *hwcRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	b.Logger().Info("Creating Creds, PATH:", "hwstaff_intl_sysadmin/OrganizationAccountAccessAgency")
	if err != nil {
		return nil, err
	}

	resp := b.Secret(TokenType).Response(map[string]interface{}{
		"access_key":     token.AccessKey,
		"secret_key":     token.SecretKey,
		"security_token": token.SecurityToken,
		"expire_time":    token.ExpireTime,
	}, map[string]interface{}{
		"access_key":     token.AccessKey,
		"secret_key":     token.SecretKey,
		"security_token": token.SecurityToken,
		"expire_time":    token.ExpireTime,
	})

	return resp, nil
}

func (b *hwcBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}
