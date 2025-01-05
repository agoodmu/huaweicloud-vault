package main

import (
	"log/slog"
	"os"

	"github.com/agoodmu/huaweicloud-vault/engine"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: engine.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             hclog.New(&hclog.LoggerOptions{Level: hclog.Debug}),
	})
	if err != nil {
		slog.Warn(err.Error())
		os.Exit(1)
	}
}
