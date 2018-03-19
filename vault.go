package samlplugin

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// zie https://github.com/eBay/fabio/blob/610f1cbfd05d5becfdb4840c2e8f432d0f240377/cert/vault_source.go

type VaultSource struct {
	Addr    string
	Refresh time.Duration

	mu         sync.Mutex
	token      string // actual token
	vaultToken string // VAULT_TOKEN env var. Might be wrapped.
}

func (s *VaultSource) client() (*api.Client, error) {
	conf := api.DefaultConfig()
	if err := conf.ReadEnvironment(); err != nil {
		return nil, err
	}
	if s.Addr != "" {
		conf.Address = s.Addr
	}
	c, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	c.SetToken(s.vaultToken)
	return c, nil
}

func NewVaultSource() (*api.Client, error) {
	v := &VaultSource{
		Addr:       vaultServer,
		vaultToken: os.Getenv("VAULT_TOKEN"),
	}
	return v.client()
}

func getVault(path string) (string, error) {
	v, err := NewVaultSource()
	if err != nil {
		return "", err
	}
	lc := v.Logical()
	s, err := lc.Read(path)
	if err != nil {
		return "", fmt.Errorf("error reading secret from Vault: %v: %v", path, err)
	}
	if s == nil {
		return "", fmt.Errorf("secret not found")
	}
	if _, ok := s.Data["value"]; !ok {
		return "", fmt.Errorf("secret missing 'value' key")
	}
	return s.Data["value"].(string), nil
}
