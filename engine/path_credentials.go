package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

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
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

const pathCredentialsHelpSyn = `
Generate a HashiCups API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a HashiCups API user tokens
based on a particular role. A role can only represent a user token,
since HashiCups doesn't have other types of tokens.
`

func (b *hwcBackend) createToken(ctx context.Context, s logical.Storage) (*hwcToken, error) {
	_, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *hwcToken

	token, err = createToken(ctx, "HIS_mujianmin")
	if err != nil {
		return nil, fmt.Errorf("error creating HashiCups token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating HashiCups token")
	}

	return token, nil
}

func (b *hwcBackend) createUserCreds(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(hwcTokenType).Response(map[string]interface{}{
		"account_name":   token.AccountName,
		"access_key":     token.AccessKey,
		"secret_key":     token.SecretKey,
		"security_token": token.SecurityToken,
	}, map[string]interface{}{
		"account_name":   token.AccountName,
		"access_key":     token.AccessKey,
		"secret_key":     token.SecretKey,
		"security_token": token.SecurityToken,
	})

	return resp, nil
}

func (b *hwcBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.createUserCreds(ctx, req)
}
