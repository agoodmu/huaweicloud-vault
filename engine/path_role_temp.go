package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

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
	roleEntry := new(hwcTempRoleEntry)
	roleName, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("the name must exist under the path %s", req.Path), nil
	}
	roleEntry.Name = roleName.(string)
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

	roleEntry := new(hwcTempRoleEntry)

	err = entry.DecodeJSON(roleEntry)
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
