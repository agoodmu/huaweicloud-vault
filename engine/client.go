package engine

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/provider"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
)

func newClient() (*iam.IamClient, error) {
	globalChain := provider.GlobalCredentialProviderChain()
	globalCred, err := globalChain.GetCredentials()
	if err != nil {
		return nil, err
	}

	hcclient, err := iam.IamClientBuilder().WithCredential(globalCred).SafeBuild()
	if err != nil {
		return nil, err
	}
	return iam.NewIamClient(hcclient), nil
}
