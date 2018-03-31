# caddy-saml

WIP
Based heavily on https://github.com/crewjam/saml and https://github.com/RobotsAndPencils/go-saml with a little bit of https://github.com/russellhaering/gosaml2

## Usecase
Our usecase is to use caddy as a reverse proxy with shibboleth support (instead of using apache,mod_shib and shibd)

## Example with cert from disk and tls enabled
```
https://:443 {
    tls /path/cert.pem /path/key.pem
    saml {
        root_url https://yourdomain.com
        disk /path/cert.pem /path/key.pem
        idp_metadata https://youridp.com/download/metadata/metadata-yourdomain.xml
        /path1 valid-user
        /path1 mail email2@domain.com
        /path1 require-all
        /path2 mail email@domain.com
        /hello uid testuid
        /hello dump-attributes
 }
proxy /hello https://backendserver.com
proxy /path1 http://backend2.com:8080
}
```


## Example with cert from vault
```
http://:80 {
    saml {
        root_url https://yourdomain.com
        idp_metadata https://youridp.com/download/metadata/metadata-yourdomain.xml
        vault_server https://vault.yourdomain.com
        vault_path secret/projects/caddy-saml/yourdomain.com
        /path1 valid-user
        /path1 require-nosession
        /path2 mail email@domain.com
        /hello uid testuid
        /hello dump-attributes
 }
proxy /hello https://backendserver.com
proxy /path1 http://backend2.com:8080
}
```

## Example with cert from disk and tls and mysql sessions enabled
```
https://:443 {
    tls /path/cert.pem /path/key.pem
    saml {
        mysql login:password@tcp(mysql.hostname.com)/caddysaml
        root_url https://yourdomain.com
        disk /path/cert.pem /path/key.pem
        idp_metadata https://youridp.com/download/metadata/metadata-yourdomain.xml
        /path1 valid-user
        /path1 mail email2@domain.com
        /path1 require-all
        /path2 mail email@domain.com
        /hello uid testuid
        /hello dump-attributes
 }
proxy /hello https://backendserver.com
proxy /path1 http://backend2.com:8080
}
```



## Issues
The OpenSSL default format for private keys is PKCS-8. We only support PKCS-1 private keys.
A private PKCS-8 formated RSA key can be converted to a private PKCS-1 formated RSA key by:

```sh
openssl rsa -in private-pkcs8-key.key -out private.key
```  
