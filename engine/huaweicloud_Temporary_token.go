package engine

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	TokenType = "HuaweiCloud_Temporary"
)

func (b *hwcBackend) huaweicloudTemporaryToken() *framework.Secret {
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
	}
}

func (b *hwcBackend) tokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
