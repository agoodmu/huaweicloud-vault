package engine

import (
	"errors"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	iamregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/region"
)

func newClient(config *hwcConfig) (*iam.IamClient, error) {
	var client *iam.IamClient
	if config.AccessKey == "" || config.SecretKey == "" || config.Region == "" {
		return nil, errors.New("missing AK/SK or Region Configuration")
	}
	globalAuth, err := global.NewCredentialsBuilder().WithAk(config.AccessKey).WithSk(config.SecretKey).SafeBuild()
	if err != nil {
		return nil, err
	}
	iamRegion, err := iamregion.SafeValueOf(config.Region)
	if err != nil {
		return nil, err
	}
	hcclient, err := iam.IamClientBuilder().WithCredential(globalAuth).WithRegion(iamRegion).SafeBuild()
	if err != nil {
		return nil, err
	}
	client = iam.NewIamClient(hcclient)

	return client, nil
}
