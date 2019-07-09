package samlplugin

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
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
		s                   *SAMLPlugin
		sMap                map[string][]string
		certPath, keyPath   string
		vaultPath, entityID string
		options             Options
	)

	options.CookieSecure = true
	options.CookieName = "__Host-cddsml-token"
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
			if c.Val() == "vault_path" {
				c.NextArg()
				vaultPath = c.Val()
			}
			if c.Val() == "vault_server" {
				c.NextArg()
				vaultServer = c.Val()
			}
			if c.Val() == "disk" {
				c.NextArg()
				certPath = c.Val()
				c.NextArg()
				keyPath = c.Val()
			}
			if c.Val() == "root_url" {
				c.NextArg()
				entityID = c.Val()
				myurl, _ := url.Parse(entityID)
				options.URL = *myurl
			}
			if c.Val() == "idp_metadata" {
				c.NextArg()
				options.IDPMetadataURL, _ = url.Parse(c.Val())
			}
			if c.Val() == "cookie_insecure" {
				c.NextArg()
				options.CookieSecure = false
			}
			if c.Val() == "cookie_name" {
				c.NextArg()
				options.CookieName = c.Val()
			}
			if c.Val() == "cookie_max_age" {
				c.NextArg()
				options.CookieMaxAge, _ = time.ParseDuration(c.Val())
			}
			if c.Val() == "sessions_enable" {
				c.NextArg()
				options.EnableSessions = true
			}
			if c.Val() == "mysql" {
				c.NextArg()
				options.DbURI = c.Val()
			}
		}

		if options.DbURI != "" {
			options.EnableSessions = true
		}

		var key, cert *pem.Block

		if certPath != "" && keyPath != "" {
			keypem, err := ioutil.ReadFile(keyPath)
			if err != nil {
				panic("Vault error: could not get" + keyPath)
			}
			certpem, err := ioutil.ReadFile(certPath)
			if err != nil {
				panic("Vault error: could not get" + certPath)
			}
			key, _ = pem.Decode(keypem)
			cert, _ = pem.Decode(certpem)
		}
		if vaultPath != "" && vaultServer != "" {
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
			key, _ = pem.Decode([]byte(keypem))
			cert, _ = pem.Decode([]byte(certpem))

		}

		options.Certificate, err = x509.ParseCertificate(cert.Bytes)
		if err != nil {
			panic(err) // TODO handle error
		}
		options.Key, err = x509.ParsePKCS1PrivateKey(key.Bytes)
		if err != nil {
			panic(err) // TODO handle error
		}
		s, _ = New(options)
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

func isAuthorizedAnd(v []string, token *AuthorizationToken) bool {
	auth := true
	for _, acl := range v {
		split := strings.Fields(acl)
		switch split[0] {
		case "valid-user":
			auth = auth && true
		case "require-all":
		default:
			if len(split) < 2 {
				return false
			}
			subauth := false
			for _, entry := range token.Attributes.GetAll(split[0]) {
				if entry == split[1] {
					subauth = true
					continue
				}
			}
			auth = auth && subauth
		}
	}
	return auth
}

func hasRequireAll(v []string) bool {
	for _, acl := range v {
		if strings.Contains(acl, "require-all") {
			return true
		}
	}
	return false
}

func hasRequireNoSession(v []string) bool {
	for _, acl := range v {
		if strings.Contains(acl, "require-nosession") {
			return true
		}
	}
	return false
}

func isAuthorized(v []string, token *AuthorizationToken) bool {
	if hasRequireAll(v) {
		return isAuthorizedAnd(v, token)
	}
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
