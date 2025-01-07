package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath string = "config"
)

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Huawei Cloud backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Huawei Cloud secret backend requires credentials for assuming agency to get
temporary credentials to access Huawei Cloud.

You must have a valid AK/SK in order to have necessary permission to assume agency.
`

type hwcConfig struct {
	Region    string `json:"region"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

func pathConfig(b *hwcBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"region": {
				Type:         framework.TypeString,
				Description:  "The region in which resouces will be created",
				Required:     true,
				DisplayAttrs: &framework.DisplayAttributes{Name: "Region", Sensitive: false},
			},
			"access_key": {
				Type:         framework.TypeString,
				Description:  "The Huawei Cloud Access Key",
				Required:     true,
				DisplayAttrs: &framework.DisplayAttributes{Name: "AccessKey", Sensitive: true},
			},
			"secret_key": {
				Type:         framework.TypeString,
				Description:  "The Huawei Cloud Secret Key",
				Required:     true,
				DisplayAttrs: &framework.DisplayAttributes{Name: "SecretKey", Sensitive: true},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *hwcBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w, path is %s", err, req.Path)
	}

	return out != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*hwcConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(hwcConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}

func (b *hwcBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"region":     config.Region,
			"access_key": config.AccessKey,
			"secret_key": config.SecretKey,
		},
	}, nil
}

func (b *hwcBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(hwcConfig)
	}

	if accessKey, ok := data.GetOk("access_key"); ok {
		config.AccessKey = accessKey.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing access_key in configuration")
	}

	if secretKey, ok := data.GetOk("secret_key"); ok {
		config.SecretKey = secretKey.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing secret_key in configuration")
	}

	if newregion, ok := data.GetOk("region"); ok {
		config.Region = newregion.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing region paramter in configuration")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *hwcBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}
