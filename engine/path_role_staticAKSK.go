package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *hwcBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, ok := d.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get data at %s: %s", req.Path, err.Error())
	}

	if entry == nil {
		return nil, fmt.Errorf("path %s does not exist", req.Path)
	}

	role := new(hwcStaticAKSKRoleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("failed to decode the data from %s: %s", req.Path, err.Error())
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":         role.Name,
			"account_name": role.AccountName,
			"permissions":  role.Permissions,
			"enabled":      role.Enabled,
			"ttl":          role.TTL.Seconds(),
			"max_ttl":      role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *hwcBackend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleEntry := new(hwcStaticAKSKRoleEntry)
	roleName, ok := d.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("missing role name")
	}
	roleEntry.Name = roleName.(string)
	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	} else {
		return nil, fmt.Errorf("account_name parameter is missing")
	}
	if permissions, ok := d.GetOk("permissions"); ok {
		roleEntry.Permissions = permissions.([]string)
	} else {
		return nil, fmt.Errorf("permissions parameter is missing")
	}

	if descriptions, ok := d.GetOk("description"); ok {
		roleEntry.Description = descriptions.(string)
	} else {
		return nil, fmt.Errorf("the description of the role is missing")
	}

	roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	roleEntry.Enabled = d.Get("enabled").(bool)

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return nil, fmt.Errorf("ttl cannot be greater than max_ttl")
	}

	if err := b.writeDataToPath(ctx, req, roleEntry); err != nil {
		return nil, fmt.Errorf("failed to write data to the path %s", req.Path)
	}

	return nil, nil
}

func (b *hwcBackend) pathStaticRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from %s", req.Path)
	}

	if entry == nil {
		return nil, fmt.Errorf("data for path %s is nil", req.Path)
	}

	roleEntry := new(hwcStaticAKSKRoleEntry)

	err = entry.DecodeJSON(&roleEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data %s: %s", req.Path, err.Error())
	}

	if accountName, ok := d.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	}

	if permissions, ok := d.GetOk("permissions"); ok {
		roleEntry.Permissions = permissions.([]string)
	}

	if enableRole, ok := d.GetOk("enabled"); ok {
		roleEntry.Enabled = enableRole.(bool)
	}

	if descriptions, ok := d.GetOk("description"); ok {
		roleEntry.Description = descriptions.(string)
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
