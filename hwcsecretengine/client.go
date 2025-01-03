package hwcsecretengine

import (
	"errors"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	iamRegion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/region"
)

func newClient(config *hwcConfig) (*iam.IamClient, error) {
	if config == nil {
		return nil, errors.New("client configuration is nil")
	}

	if config.Region == "" {
		return nil, errors.New("region is not defined")
	}

	if config.AccessKey == "" || config.SecretKey == "" {
		return nil, errors.New("AK/SK is not provided")
	}

	globalAuth, err := global.NewCredentialsBuilder().WithAk(config.AccessKey).WithSk(config.SecretKey).SafeBuild()
	if err != nil {
		return nil, err
	}
	hcclient, err := iam.IamClientBuilder().WithCredential(globalAuth).WithRegion(iamRegion.AP_SOUTHEAST_3).SafeBuild()
	if err != nil {
		return nil, err
	}
	return iam.NewIamClient(hcclient), nil
}
