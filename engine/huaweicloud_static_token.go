package engine

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	StaticAKSK string = "HuaweiCloud_StaticAKSK"
)

func (b *hwcBackend) huaweicloudStaticAKSK() *framework.Secret {
	return &framework.Secret{
		Type: StaticAKSK,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud Access Key",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Huawei Cloud Secret Key",
			},
			"expire_time": {
				Type:        framework.TypeString,
				Description: "Token expires time",
			},
		},
		Revoke: b.staticAKSKRevoke,
	}
}

func (b *hwcBackend) staticAKSKRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
