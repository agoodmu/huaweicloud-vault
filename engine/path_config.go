package engine

import (
	"context"
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
	Region           string `json:"region"`
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
	ManagementAgency string `json:"management_agency"`
}

func pathConfig(b *hwcBackend) *framework.Path {
	return &framework.Path{
		Pattern: configStoragePath,
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
			"management_agency": {
				Type:         framework.TypeString,
				Description:  "The delegated agency in member account",
				Required:     false,
				DisplayAttrs: &framework.DisplayAttributes{Name: "ManagementAgency", Sensitive: false},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigUpdate},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.deletePath},
		},
		ExistenceCheck:  b.pathExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *hwcBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configData, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get data at %s: %s", req.Path, err.Error())
	}
	if configData == nil {
		return nil, fmt.Errorf("configuration data does not exist")
	}

	config := new(hwcConfig)
	err = configData.DecodeJSON(config)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"region":            config.Region,
			"access_key":        config.AccessKey,
			"secret_key":        config.SecretKey,
			"management_agency": config.ManagementAgency,
		},
	}, nil
}

func (b *hwcBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := new(hwcConfig)

	if accessKey, ok := data.GetOk("access_key"); ok {
		config.AccessKey = accessKey.(string)
	} else {
		return nil, fmt.Errorf("missing access_key in configuration")
	}

	if secretKey, ok := data.GetOk("secret_key"); ok {
		config.SecretKey = secretKey.(string)
	} else {
		return nil, fmt.Errorf("missing secret_key in configuration")
	}

	if newregion, ok := data.GetOk("region"); ok {
		config.Region = newregion.(string)
	} else {
		return nil, fmt.Errorf("missing region paramter in configuration")
	}

	if managementAgency, ok := data.GetOk("management_agency"); ok {
		config.ManagementAgency = managementAgency.(string)
	}

	err := b.writeDataToPath(ctx, req, &config)

	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *hwcBackend) pathConfigUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configData, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration data: %s", err.Error())
	}

	config := new(hwcConfig)
	err = configData.DecodeJSON(config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode configuration data at %s", req.Path)
	}

	if accessKey, ok := data.GetOk("access_key"); ok {
		config.AccessKey = accessKey.(string)
	}

	if secretKey, ok := data.GetOk("secret_key"); ok {
		config.SecretKey = secretKey.(string)
	}

	if newregion, ok := data.GetOk("region"); ok {
		config.Region = newregion.(string)
	}

	if managementAgency, ok := data.GetOk("management_agency"); ok {
		config.ManagementAgency = managementAgency.(string)
	}

	err = b.writeDataToPath(ctx, req, &config)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
