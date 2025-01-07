package engine

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
)

const backendHelp = `
The Huawei Cloud secrets backend dynamically generates temporary Access Key and Secret Key.
After mounting this backend, credentials to manage Huawei Cloud temporary Access Key and Secret Key
must be configured with the "config/" endpoints.
`

type hwcBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *iam.IamClient
}

func (b *hwcBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *hwcBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *hwcBackend) getClient(ctx context.Context, s logical.Storage) (*iam.IamClient, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errors.New("backend configuration does not exists")
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

func backend() *hwcBackend {
	var b = hwcBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths:       framework.PathAppend(pathRole(&b), pathCredentials(&b), []*framework.Path{pathConfig(&b)}),
		Secrets:     []*framework.Secret{b.huaweicloud_Token()},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
