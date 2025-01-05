package engine

import (
	"errors"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/provider"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
)

func newClient(config *hwcConfig) (*iam.IamClient, error) {
	var client *iam.IamClient
	if config.UseAKSK {
		if config.AccessKey == "" || config.SecretKey == "" {
			return nil, errors.New("missing AK/SK Configuration")
		}
		globalAuth, err := global.NewCredentialsBuilder().WithAk(config.AccessKey).WithSk(config.SecretKey).SafeBuild()
		if err != nil {
			return nil, err
		}
		hcclient, err := iam.IamClientBuilder().WithCredential(globalAuth).SafeBuild()
		if err != nil {
			return nil, err
		}
		client = iam.NewIamClient(hcclient)

	} else {
		globalChain := provider.GlobalCredentialProviderChain()
		globalCred, err := globalChain.GetCredentials()
		if err != nil {
			return nil, err
		}

		hcclient, err := iam.IamClientBuilder().WithCredential(globalCred).SafeBuild()
		if err != nil {
			return nil, err
		}
		client = iam.NewIamClient(hcclient)
	}

	return client, nil
}
