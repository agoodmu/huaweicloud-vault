package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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
