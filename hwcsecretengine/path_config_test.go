package hwcsecretengine

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const (
	region     = "ap-southeast-3"
	access_key = "Testing!123"
	secret_key = "http://localhost:19090"
)

func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Configuration", func(t *testing.T) {
		err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"region":     region,
			"access_key": access_key,
			"secret_key": secret_key,
		})

		assert.NoError(t, err)
	})
}

func testConfigCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}
