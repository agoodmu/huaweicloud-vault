package hwcsecretengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	hwcTokenType = "hwc_token"
)

type hwcToken struct {
	Username      string `json:"username"`
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	SecurityToken string `json:"security_token"`
}

func (b *hwcBackend) hwcToken() *framework.Secret {
	return &framework.Secret{
		Type: hwcTokenType,
		Fields: map[string]*framework.FieldSchema{
			"AccessKey": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud AccessKey",
			},
			"SecretKey": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud SecretKey",
			},
			"SecurityToken": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud SecurityToken",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

func deleteToken(ctx context.Context, token string) error {
	fmt.Println(token)
	return nil
}

func (b *hwcBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//	client, err := b.getClient(ctx, req.Storage)
	//	if err != nil {
	//		return nil, fmt.Errorf("error getting client: %w", err)
	///	}

	token := ""
	tokenRaw, ok := req.Secret.InternalData["AccessKey"]
	if ok {
		token, ok = tokenRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for token in secret internal data")
		}
	}

	if err := deleteToken(ctx, token); err != nil {
		return nil, fmt.Errorf("error revoking user token: %w", err)
	}
	return nil, nil
}

func createToken(ctx context.Context, username string) (*hwcToken, error) {
	tokenID := uuid.New().String()

	return &hwcToken{
		Username:      username,
		AccessKey:     tokenID,
		SecretKey:     tokenID,
		SecurityToken: tokenID,
	}, nil
}

func (b *hwcBackend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
