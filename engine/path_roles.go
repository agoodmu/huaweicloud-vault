package engine

import (
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

type hwcStaticAKSKRoleEntry struct {
	Name        string        `json:"name"`
	AccountName string        `json:"account_name"`
	Permissions []string      `json:"permissions"`
	Enabled     bool          `json:"enabled"`
	Description string        `json:"description"`
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
				"enabled": {
					Type:        framework.TypeBool,
					Description: "If the AK/SK is enabled",
					Required:    false,
					Default:     true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Describe the usage of the AK/SK",
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
			ExistenceCheck:  b.pathExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/static/" + framework.GenericNameRegex("name"),
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
				"permissions": {
					Type:        framework.TypeStringSlice,
					Description: "The Huawei Cloud permissions that associate with the role",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
					Required:    false,
					Default:     2592000,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticRoleRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleUpdate},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.deletePath},
			},
			ExistenceCheck:  b.pathExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.listPaths},
			},
			ExistenceCheck:  b.pathExistenceCheck,
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}
