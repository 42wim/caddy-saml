# caddy-saml

WIP
Based heavily on https://github.com/crewjam/saml and https://github.com/RobotsAndPencils/go-saml

## Usecase
Our usecase is to use caddy as a reverse proxy with shibboleth support (instead of using apache,mod_shib and shibd)

## Example
```
https://yourdomain.com:443 {
    saml {
        entityid https://yourdomain.com/saml/metadata
        idpmetadata https://youridp.com/download/metadata/metadata-yourdomain.xml
        vaultserver https://vault.yourdomain.com
        vaultpath secret/projects/caddy-saml/yourdomain.com
        /path1 valid-user
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
