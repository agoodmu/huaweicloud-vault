package engine

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	TokenType = "HuaweiCloud_Temporary"
)

type hwcToken struct {
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	SecurityToken string `json:"security_token"`
	ExpireTime    string `json:"expire_time"`
}

func (b *hwcBackend) huaweicloud_Token() *framework.Secret {
	return &framework.Secret{
		Type: TokenType,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud Access Key",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud Secret Key",
			},
			"security_token": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud Security Token",
			},
			"expire_time": {
				Type:        framework.TypeString,
				Description: "Token expires time",
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
	tokenRaw, ok := req.Secret.InternalData["access_key"]
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

func createToken(ctx context.Context, account string) (*hwcToken, error) {
	tokenID := uuid.New().String()

	return &hwcToken{
		AccessKey:     tokenID,
		SecretKey:     tokenID,
		SecurityToken: tokenID,
	}, nil
}

func (b *hwcBackend) tokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	resp := &logical.Response{Secret: req.Secret}

	return resp, nil
}
