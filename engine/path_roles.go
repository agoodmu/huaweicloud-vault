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

type hwcRoleEntry struct {
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
					Default:     900,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
					Required:    false,
					Default:     86400,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleUpdate},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *hwcBackend) getRole(ctx context.Context, s logical.Storage, name string) (*hwcRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role hwcRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func (b *hwcBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":         entry.Name,
			"account_name": entry.AccountName,
			"agency_name":  entry.AgencyName,
			"ttl":          entry.TTL.Seconds(),
			"max_ttl":      entry.MaxTTL.Seconds(),
		},
	}, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *hwcRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (b *hwcBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &hwcRoleEntry{Name: name.(string)}
	}

	if agencyName, ok := d.GetOk("agency_name"); ok {
		roleEntry.AgencyName = agencyName.(string)
	} else {
		return logical.ErrorResponse("missing agency_name"), nil
	}

	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	} else {
		return logical.ErrorResponse("missing account_name"), nil
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else {
		return logical.ErrorResponse("missing ttl"), nil
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else {
		return logical.ErrorResponse("missing max_ttl"), nil
	}

	if roleEntry.TTL < 900 {
		return logical.ErrorResponse("ttl must be greater than 900"), nil
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *hwcBackend) pathRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		return logical.ErrorResponse("role is not found"), nil
	}

	if agencyName, ok := d.GetOk("agency_name"); ok {
		roleEntry.AgencyName = agencyName.(string)
	}

	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
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

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *hwcBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting hashiCups role: %w", err)
	}

	return nil, nil
}

func (b *hwcBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
