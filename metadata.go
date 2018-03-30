// based on https://github.com/RobotsAndPencils/go-saml/metadata.go
package samlplugin

import (
	"encoding/base64"
	"encoding/xml"
)

func (s *SAMLPlugin) GetEntityDescriptor() (string, error) {
	d := EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityId: "https://" + s.ServiceProvider.MetadataURL.Hostname() + s.ServiceProvider.MetadataURL.Path,

		Extensions: Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",
		},
		SPSSODescriptor: SPSSODescriptor{
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			SigningKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "signing",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: base64.StdEncoding.EncodeToString(s.ServiceProvider.Certificate.Raw),
						},
					},
				},
			},
			EncryptionKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "encryption",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: base64.StdEncoding.EncodeToString(s.ServiceProvider.Certificate.Raw),
						},
					},
				},
			},
			// SingleLogoutService{
			// 	XMLName: xml.Name{
			// 		Local: "md:SingleLogoutService",
			// 	},
			// 	Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			// 	Location: "---TODO---",
			// },
			AssertionConsumerServices: []AssertionConsumerService{
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: "https://" + s.ServiceProvider.MetadataURL.Hostname() + s.ServiceProvider.AcsURL.Path,
					Index:    "0",
				},
			},
			SingleLogoutService: SingleLogoutService{
				XMLName: xml.Name{
					Local: "md:SingleLogoutService",
				},
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: "https://" + s.ServiceProvider.MetadataURL.Hostname() + s.ServiceProvider.SloURL.Path,
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	///newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	return string(b), nil
}
