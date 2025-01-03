package main

import (
	"log/slog"
	"os"

	hwc "github.com/agoodmu/vault-iic/hwcsecretengine"
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
		BackendFactoryFunc: hwc.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             hclog.New(&hclog.LoggerOptions{Level: hclog.Info}),
	})
	if err != nil {
		slog.Warn(err.Error())
		os.Exit(1)
	}
}
