package hwcsecretengine

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

func (b *hwcBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *hwcRoleEntry) (*hwcToken, error) {
	_, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *hwcToken

	token, err = createToken(ctx, roleEntry.Username)
	if err != nil {
		return nil, fmt.Errorf("error creating HashiCups token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating HashiCups token")
	}

	return token, nil
}

func (b *hwcBackend) createUserCreds(ctx context.Context, req *logical.Request, role *hwcRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(hwcTokenType).Response(map[string]interface{}{
		"access_key":     token.AccessKey,
		"secret_key":     token.SecretKey,
		"security_token": token.SecurityToken,
	}, map[string]interface{}{
		"access_key":     token.AccessKey,
		"secret_key":     token.SecretKey,
		"security_token": token.SecurityToken,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

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
