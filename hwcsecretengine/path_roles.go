package hwcsecretengine

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
	Username string        `json:"username"`
	UserID   int           `json:"user_id"`
	Token    string        `json:"token"`
	TokenID  string        `json:"token_id"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`
}

func (r *hwcRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":      r.TTL.Seconds(),
		"max_ttl":  r.MaxTTL.Seconds(),
		"username": r.Username,
	}
	return respData
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
				"username": {
					Type:        framework.TypeString,
					Description: "The username for the HashiCups product API",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
			},
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
		Data: entry.toResponseData(),
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
		roleEntry = &hwcRoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if username, ok := d.GetOk("username"); ok {
		roleEntry.Username = username.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing username in role")
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
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
