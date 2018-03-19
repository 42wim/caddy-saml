package samlplugin

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"net/http"
	"net/url"
	"strings"
)

func init() {
	plug := caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	}
	caddy.RegisterPlugin("saml", plug)
}

var vaultServer string

func setup(c *caddy.Controller) (err error) {
	var (
		s                       *SAMLPlugin
		sMap                    map[string][]string
		vaultPath, entityID     string
		rootURL, idpMetadataURL *url.URL
	)

	for c.Next() {
		if s != nil {
			return c.Err("Cannot define saml more than once per server")
		}
		sMap = make(map[string][]string)
		for c.NextBlock() {
			if strings.HasPrefix(c.Val(), "/") {
				url := c.Val()
				c.NextArg()
				what := c.Val()
				c.NextArg()
				acl := c.Val()
				sMap[url] = append(sMap[url], what+" "+acl)
			}
			if c.Val() == "vaultpath" {
				c.NextArg()
				vaultPath = c.Val()
			}
			if c.Val() == "vaultserver" {
				c.NextArg()
				vaultServer = c.Val()
			}
			if c.Val() == "entityid" {
				c.NextArg()
				entityID = c.Val()
				rootURL, _ = url.Parse(entityID)
			}
			if c.Val() == "idpmetadata" {
				c.NextArg()
				idpMetadataURL, _ = url.Parse(c.Val())
			}
		}

		// use asset data
		var keypem, certpem string
		keypem, err = getVault(vaultPath + "/sp-key")
		if err != nil {
			panic("Vault error: could not get" + vaultPath)
		}

		certpem, err = getVault(vaultPath + "/sp-cert")
		if err != nil {
			panic("Vault error: could not get" + vaultPath)
		}

		key, _ := pem.Decode([]byte(keypem))
		cert, _ := pem.Decode([]byte(certpem))

		x509Cert, err := x509.ParseCertificate(cert.Bytes)
		if err != nil {
			panic(err) // TODO handle error
		}
		privKey, err := x509.ParsePKCS1PrivateKey(key.Bytes)
		if err != nil {
			panic(err) // TODO handle error
		}
		s, _ = New(Options{
			URL:            *rootURL,
			Key:            privKey,
			Certificate:    x509Cert,
			IDPMetadataURL: idpMetadataURL,
		})

		s.Map = sMap
	}

	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		s.next = next
		return s
	}
	cfg.AddMiddleware(mid)
	return nil
}

func setHeaders(r *http.Request, token *AuthorizationToken) {
	for k, v := range token.Attributes {
		r.Header.Set(k, strings.Join(v, ","))
	}
	r.Header.Set("REMOTE_USER", token.Attributes.Get("eduPersonPrincipalName"))
}

func dumpAttributes(v []string) bool {
	for _, acl := range v {
		if strings.Contains(acl, "dump-attributes") {
			return true
		}
	}
	return false
}

func isAuthorized(v []string, token *AuthorizationToken) bool {
	for _, acl := range v {
		split := strings.Fields(acl)
		switch split[0] {
		case "valid-user":
			return true
		default:
			if len(split) < 2 {
				return false
			}
			for _, entry := range token.Attributes.GetAll(split[0]) {
				if entry == split[1] {
					return true
				}
			}
		}
	}
	return false
}
