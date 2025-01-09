package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating HashiCups tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate HashiCups tokens.
You can configure a role to manage a user's token by setting the username field.
`
	pathRoleListHelpSynopsis    = `List the existing roles in HashiCups backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)

type hwcTempRoleEntry struct {
	Name        string        `json:"name"`
	AccountName string        `json:"account_name"`
	AgencyName  string        `json:"agency_name"`
	TTL         time.Duration `json:"ttl"`
	MaxTTL      time.Duration `json:"max_ttl"`
}

func pathRole(b *hwcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"account_name": {
					Type:        framework.TypeString,
					Description: "The domain name of the target account",
					Required:    true,
				},
				"agency_name": {
					Type:        framework.TypeString,
					Description: "The agency name which will be assumed by the plugin",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
					Required:    false,
					Default:     7200,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
					Required:    false,
					Default:     86400,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathTempRoleRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathTempRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathTempRoleUpdate},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.deletePath},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.listPaths},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *hwcBackend) pathTempRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("the name must exist under the path %s", req.Path), fmt.Errorf("missing role name")
	}

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return logical.ErrorResponse("failed to read data from path %s: %s", req.Path, err.Error()), err
	}

	if entry == nil {
		return logical.ErrorResponse("path %s does not exist", req.Path), nil
	}

	var role hwcTempRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return logical.ErrorResponse("failed to decode the data from %s", req.Path), err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":         role.Name,
			"account_name": role.AccountName,
			"agency_name":  role.AgencyName,
			"ttl":          role.TTL.Seconds(),
			"max_ttl":      role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *hwcBackend) pathTempRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var roleEntry hwcTempRoleEntry
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("the name must exist under the path %s", req.Path), nil
	}

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from %s", req.Path)
	}

	if entry != nil {
		return nil, fmt.Errorf("the path already exists, use patch subcommand to modify it if you want to change the path")
	}

	roleEntry = hwcTempRoleEntry{Name: name.(string)}
	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	} else {
		return nil, fmt.Errorf("account_name parameter is missing")
	}
	if agencyName, ok := d.GetOk("agency_name"); ok {
		roleEntry.AgencyName = agencyName.(string)
	} else {
		return nil, fmt.Errorf("agency_name parameter is missing")
	}

	roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second

	if roleEntry.TTL < 900 {
		return logical.ErrorResponse("ttl must be greater than 900"), nil
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := b.writeDataToPath(ctx, req, roleEntry); err != nil {
		return nil, fmt.Errorf("failed to write data to the path %s", req.Path)
	}

	return nil, nil
}

func (b *hwcBackend) pathTempRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from %s", req.Path)
	}

	if entry == nil {
		return nil, fmt.Errorf("data for path %s is nil", req.Path)
	}

	var roleEntry *hwcTempRoleEntry

	err = entry.DecodeJSON(&roleEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data %s: %s", req.Path, err.Error())
	}

	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	}

	if agencyName, ok := d.GetOk("agency_name"); ok {
		roleEntry.AgencyName = agencyName.(string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := b.writeDataToPath(ctx, req, roleEntry); err != nil {
		return nil, fmt.Errorf("failed to write data to the path %s", req.Path)
	}
	return nil, nil
}
