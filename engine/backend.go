package engine

import (
	"context"
	"fmt"
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

	configData, err := b.readDataFromPath(ctx, s, configStoragePath)
	if err != nil {
		return nil, err
	}

	if configData == nil {
		return nil, fmt.Errorf("backend configuration does not exists")
	}
	config := new(hwcConfig)

	err = configData.DecodeJSON(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode configuration data: %s", configStoragePath)
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
		Secrets:     []*framework.Secret{b.huaweicloudTemporaryToken(), b.huaweicloudStaticAKSK()},
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

func (b *hwcBackend) writeDataToPath(ctx context.Context, s logical.Storage, path string, data interface{}) error {
	entry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for the path %s", path)
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func (b *hwcBackend) readDataFromPath(ctx context.Context, s logical.Storage, path string) (*logical.StorageEntry, error) {
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (b *hwcBackend) deletePath(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, ok := d.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("data for path %s does not exist", req.Path)
	}
	err := req.Storage.Delete(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to delete %s: %s", req.Path, err.Error())
	}

	return nil, nil
}

func (b *hwcBackend) listPaths(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

// pathExistenceCheck verifies if the path exists.
func (b *hwcBackend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w, path is %s", err, req.Path)
	}

	return out != nil, nil
}
