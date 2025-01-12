package engine

import (
	"fmt"

	org "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/organizations/v1"
	orgmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/organizations/v1/model"
)

func getAccountId(client *org.OrganizationsClient, name string) (*string, error) {
	listResult, err := client.ListAccounts(&orgmodel.ListAccountsRequest{})
	if err != nil {
		return nil, err
	}

	for _, account := range *listResult.Accounts {
		if account.Name == name {
			return &account.Id, nil
		}
	}
	return nil, fmt.Errorf("account %s does not belong to this organization", name)
}
