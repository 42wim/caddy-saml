package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/42wim/crewjam-saml/logger"
	"github.com/42wim/crewjam-saml/xmlenc"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// NameIDFormat is the format of the id
type NameIDFormat string

// Element returns an XML element representation of n.
func (n NameIDFormat) Element() *etree.Element {
	el := etree.NewElement("")
	el.SetText(string(n))
	return el
}

// Name ID formats
const (
	UnspecifiedNameIDFormat  NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
	TransientNameIDFormat    NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	EmailAddressNameIDFormat NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
	PersistentNameIDFormat   NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// ServiceProvider implements SAML Service provider.
//
// In SAML, service providers delegate responsibility for identifying
// clients to an identity provider. If you are writing an application
// that uses passwords (or whatever) stored somewhere else, then you
// are service provider.
//
// See the example directory for an example of a web application using
// the service provider interface.
type ServiceProvider struct {
	// Key is the RSA private key we use to sign requests.
	Key *rsa.PrivateKey

	// Certificate is the RSA public part of Key.
	Certificate *x509.Certificate

	// MetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	MetadataURL url.URL

	// AcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	AcsURL url.URL

	// SloURL is the full URL to the SAML Single Logout Service endpoint
	// on this host, i.e. https://example.com/saml/slo
	SloURL url.URL

	// IDPMetadata is the metadata from the identity provider.
	IDPMetadata *EntityDescriptor

	// AuthnNameIDFormat is the format used in the NameIDPolicy for
	// authentication requests
	AuthnNameIDFormat NameIDFormat

	// MetadataValidDuration is a duration used to calculate validUntil
	// attribute in the metadata endpoint
	MetadataValidDuration time.Duration

	// Logger is used to log messages for example in the event of errors
	Logger logger.Interface

	// ForceAuthn allows you to force re-authentication of users even if the user
	// has a SSO session at the IdP.
	ForceAuthn *bool

	// signing context
	signingContextMu sync.RWMutex
	signingContext   *dsig.SigningContext
}

// MaxIssueDelay is the longest allowed time between when a SAML assertion is
// issued by the IDP and the time it is received by ParseResponse. This is used
// to prevent old responses from being replayed (while allowing for some clock
// drift between the SP and IDP).
const MaxIssueDelay = time.Second * 90

// MaxClockSkew allows for leeway for clock skew between the IDP and SP when
// validating assertions. It defaults to 180 seconds (matches shibboleth).
var MaxClockSkew = time.Second * 180

// DefaultValidDuration is how long we assert that the SP metadata is valid.
const DefaultValidDuration = time.Hour * 24 * 2

// DefaultCacheDuration is how long we ask the IDP to cache the SP metadata.
const DefaultCacheDuration = time.Hour * 24 * 1

// Metadata returns the service provider metadata
func (sp *ServiceProvider) Metadata() *EntityDescriptor {
	validDuration := DefaultValidDuration
	if sp.MetadataValidDuration > 0 {
		validDuration = sp.MetadataValidDuration
	}

	authnRequestsSigned := false
	wantAssertionsSigned := true
	validUntil := TimeNow().Add(validDuration)
	return &EntityDescriptor{
		EntityID:   sp.MetadataURL.String(),
		ValidUntil: validUntil,

		SPSSODescriptors: []SPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									Certificate: base64.StdEncoding.EncodeToString(sp.Certificate.Raw),
								},
							},
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									Certificate: base64.StdEncoding.EncodeToString(sp.Certificate.Raw),
								},
								EncryptionMethods: []EncryptionMethod{
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
								},
							},
						},
						ValidUntil: validUntil,
					},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,

				AssertionConsumerServices: []IndexedEndpoint{
					{
						Binding:  HTTPPostBinding,
						Location: sp.AcsURL.String(),
						Index:    1,
					},
				},
			},
		},
	}
}

// MakeRedirectAuthenticationRequest creates a SAML authentication request using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the auth process.
func (sp *ServiceProvider) MakeRedirectAuthenticationRequest(relayState string) (*url.URL, error) {
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPRedirectBinding))
	if err != nil {
		return nil, err
	}
	return req.Redirect(relayState), nil
}

// MakeRedirectLogoutResponse creates a SAML authentication request using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to end the logout process.
func (sp *ServiceProvider) MakeRedirectLogoutResponse(inResponseTo string) (*url.URL, error) {
	resp, err := sp.MakeLogoutResponse(inResponseTo, sp.GetSLOBindingLocation(HTTPRedirectBinding))
	if err != nil {
		return nil, err
	}

	// create the redirect URL (base64 / flate query)
	url := resp.Redirect()

	// do the signing
	// this code comes from github.com/russellhaering/gosaml2
	query := url.Query()
	ctx := sp.SigningContext()
	query.Add("SigAlg", ctx.GetSignatureMethodIdentifier())
	var rawSignature []byte
	if rawSignature, err = ctx.SignString(query.Encode()); err != nil {
		return url, fmt.Errorf("unable to sign query string of redirect URL: %v", err)
	}

	// Now add base64 encoded Signature
	query.Add("Signature", base64.StdEncoding.EncodeToString(rawSignature))

	url.RawQuery = query.Encode()
	return url, nil
}

// Redirect returns a URL suitable for using the redirect binding with the request
func (req *AuthnRequest) Redirect(relayState string) *url.URL {
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	if _, err := doc.WriteTo(w2); err != nil {
		panic(err)
	}
	w2.Close()
	w1.Close()

	rv, _ := url.Parse(req.Destination)

	query := rv.Query()
	query.Set("SAMLRequest", string(w.Bytes()))
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	rv.RawQuery = query.Encode()

	return rv
}

// GetSSOBindingLocation returns URL for the IDP's Single Sign On Service binding
// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
func (sp *ServiceProvider) GetSSOBindingLocation(binding string) string {
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, singleSignOnService := range idpSSODescriptor.SingleSignOnServices {
			if singleSignOnService.Binding == binding {
				return singleSignOnService.Location
			}
		}
	}
	return ""
}

// GetSLOBindingLocation returns URL for the IDP's Single Logout Service binding
// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
func (sp *ServiceProvider) GetSLOBindingLocation(binding string) string {
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, singleLogoutService := range idpSSODescriptor.SingleLogoutServices {
			if singleLogoutService.Binding == binding {
				return singleLogoutService.Location
			}
		}
	}
	return ""
}

// getIDPSigningCert returns the certificate which we can use to verify things
// signed by the IDP in PEM format, or nil if no such certificate is found.
func (sp *ServiceProvider) getIDPSigningCert() (*x509.Certificate, error) {
	certStr := ""
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, keyDescriptor := range idpSSODescriptor.KeyDescriptors {
			if keyDescriptor.Use == "signing" {
				certStr = keyDescriptor.KeyInfo.Certificate
				break
			}
		}
	}

	// If there are no explicitly signing certs, just return the first
	// non-empty cert we find.
	if certStr == "" {
		for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
			for _, keyDescriptor := range idpSSODescriptor.KeyDescriptors {
				if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
					certStr = keyDescriptor.KeyInfo.Certificate
					break
				}
			}
		}
	}

	if certStr == "" {
		return nil, errors.New("cannot find any signing certificate in the IDP SSO descriptor")
	}

	// cleanup whitespace
	certStr = regexp.MustCompile(`\s+`).ReplaceAllString(certStr, "")
	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %s", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return parsedCert, nil
}

// MakeAuthenticationRequest produces a new AuthnRequest object for idpURL.
func (sp *ServiceProvider) MakeAuthenticationRequest(idpURL string) (*AuthnRequest, error) {
	var nameIDFormat string
	switch sp.AuthnNameIDFormat {
	case "":
		// To maintain library back-compat, use "transient" if unset.
		nameIDFormat = string(TransientNameIDFormat)
	case UnspecifiedNameIDFormat:
		// Spec defines an empty value as "unspecified" so don't set one.
	default:
		nameIDFormat = string(sp.AuthnNameIDFormat)
	}

	allowCreate := true
	req := AuthnRequest{
		AssertionConsumerServiceURL: sp.AcsURL.String(),
		Destination:                 idpURL,
		ProtocolBinding:             HTTPPostBinding, // default binding for the response
		ID:                          fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant:                TimeNow(),
		Version:                     "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  sp.MetadataURL.String(),
		},
		NameIDPolicy: &NameIDPolicy{
			AllowCreate: &allowCreate,
			// TODO(ross): figure out exactly policy we need
			// urn:mace:shibboleth:1.0:nameIdentifier
			// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
			Format: &nameIDFormat,
		},
		ForceAuthn: sp.ForceAuthn,
	}
	return &req, nil
}

// MakePostAuthenticationRequest creates a SAML authentication request using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser to initiate the login process.
func (sp *ServiceProvider) MakePostAuthenticationRequest(relayState string) ([]byte, error) {
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPPostBinding))
	if err != nil {
		return nil, err
	}
	return req.Post(relayState), nil
}

// Post returns an HTML form suitable for using the HTTP-POST binding with the request
func (req *AuthnRequest) Post(relayState string) []byte {
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	reqBuf, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	encodedReqBuf := base64.StdEncoding.EncodeToString(reqBuf)

	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))
	data := struct {
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		URL:         req.Destination,
		SAMLRequest: encodedReqBuf,
		RelayState:  relayState,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}

	return rv.Bytes()
}

// AssertionAttributes is a list of AssertionAttribute
type AssertionAttributes []AssertionAttribute

// Get returns the assertion attribute whose Name or FriendlyName
// matches name, or nil if no matching attribute is found.
func (aa AssertionAttributes) Get(name string) *AssertionAttribute {
	for _, attr := range aa {
		if attr.Name == name {
			return &attr
		}
		if attr.FriendlyName == name {
			return &attr
		}
	}
	return nil
}

// AssertionAttribute represents an attribute of the user extracted from
// a SAML Assertion.
type AssertionAttribute struct {
	FriendlyName string
	Name         string
	Value        string
}

// InvalidResponseError is the error produced by ParseResponse when it fails.
// The underlying error is in PrivateErr. Response is the response as it was
// known at the time validation failed. Now is the time that was used to validate
// time-dependent parts of the assertion.
type InvalidResponseError struct {
	PrivateErr error
	Response   string
	Now        time.Time
}

func (ivr *InvalidResponseError) Error() string {
	return fmt.Sprintf("Authentication failed")
}

// InvalidRequestError is the error produced by ParseLogoutRequest when it fails.
// The underlying error is in PrivateErr. Request is the request as it was
// known at the time validation failed. Now is the time that was used to validate
// time-dependent parts of the assertion.
type InvalidRequestError struct {
	PrivateErr error
	Request    string
	Now        time.Time
}

func (ivr *InvalidRequestError) Error() string {
	return fmt.Sprintf("Authentication failed")
}

// ParseResponse extracts the SAML IDP response received in req, validates
// it, and returns the verified attributes of the request.
//
// This function handles decrypting the message, verifying the digital
// signature on the assertion, and verifying that the specified conditions
// and properties are met.
//
// If the function fails it will return an InvalidResponseError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure the diagnostic
// information, the Error() method returns a static string.
func (sp *ServiceProvider) ParseResponse(req *http.Request, possibleRequestIDs []string) (*Assertion, error) {
	now := TimeNow()
	retErr := &InvalidResponseError{
		Now:      now,
		Response: req.PostForm.Get("SAMLResponse"),
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
		return nil, retErr
	}
	retErr.Response = string(rawResponseBuf)

	// do some validation first before we decrypt
	resp := Response{}
	if err := xml.Unmarshal(rawResponseBuf, &resp); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal response: %s", err)
		return nil, retErr
	}
	if resp.Destination != sp.AcsURL.String() {
		retErr.PrivateErr = fmt.Errorf("`Destination` does not match AcsURL (expected %q)", sp.AcsURL.String())
		return nil, retErr
	}

	requestIDvalid := false
	for _, possibleRequestID := range possibleRequestIDs {
		if resp.InResponseTo == possibleRequestID {
			requestIDvalid = true
		}
	}
	if !requestIDvalid {
		retErr.PrivateErr = fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs)
		return nil, retErr
	}

	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		retErr.PrivateErr = fmt.Errorf("IssueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay))
		return nil, retErr
	}
	if resp.Issuer.Value != sp.IDPMetadata.EntityID {
		retErr.PrivateErr = fmt.Errorf("Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
		return nil, retErr
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		retErr.PrivateErr = fmt.Errorf("Status code was not %s", StatusSuccess)
		return nil, retErr
	}

	var assertion *Assertion
	if resp.EncryptedAssertion == nil {

		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		// TODO(ross): verify that the namespace is urn:oasis:names:tc:SAML:2.0:protocol
		responseEl := doc.Root()
		if responseEl.Tag != "Response" {
			retErr.PrivateErr = fmt.Errorf("expected to find a response object, not %s", doc.Root().Tag)
			return nil, retErr
		}

		if err = sp.validateSigned(responseEl); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		assertion = resp.Assertion
	}

	// decrypt the response
	if resp.EncryptedAssertion != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
		el := doc.FindElement("//EncryptedAssertion/EncryptedData")
		plaintextAssertion, err := xmlenc.Decrypt(sp.Key, el)
		if err != nil {
			retErr.PrivateErr = fmt.Errorf("failed to decrypt response: %s", err)
			return nil, retErr
		}
		retErr.Response = string(plaintextAssertion)

		doc = etree.NewDocument()
		if err := doc.ReadFromBytes(plaintextAssertion); err != nil {
			retErr.PrivateErr = fmt.Errorf("cannot parse plaintext response %v", err)
			return nil, retErr
		}

		if err := sp.validateSigned(doc.Root()); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		assertion = &Assertion{}
		if err := xml.Unmarshal(plaintextAssertion, assertion); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
	}

	if err := sp.validateAssertion(assertion, possibleRequestIDs, now); err != nil {
		retErr.PrivateErr = fmt.Errorf("assertion invalid: %s", err)
		return nil, retErr
	}

	return assertion, nil
}

// ParseLogoutRequest extracts the SAML IDP logout request received in req, validates
// it, and returns the NameID and Request ID
//
// This function handles decrypting the message, verifying the digital
// signature on the assertion, and verifying that the specified conditions
// and properties are met.
//
// If the function fails it will return an InvalidRequestError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure the diagnostic
// information, the Error() method returns a static string.
func (sp *ServiceProvider) ParseLogoutRequest(r *http.Request) (*NameID, string, error) {
	var nameID *NameID
	now := TimeNow()
	retErr := &InvalidRequestError{
		Now:     now,
		Request: r.PostForm.Get("SAMLRequest"),
	}

	rawRequestBuf, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
		return nil, "", retErr
	}
	retErr.Request = string(rawRequestBuf)

	// do some validation first before we decrypt
	req := LogoutRequest{}
	if err := xml.Unmarshal(rawRequestBuf, &req); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal request: %s", err)
		return nil, "", retErr
	}
	//fmt.Printf("ParseLogoutRequest %#v\n", req)

	if req.Destination != sp.SloURL.String() {
		retErr.PrivateErr = fmt.Errorf("`Destination` does not match SloURL (expected %q)", sp.SloURL.String())
		return nil, "", retErr
	}

	if req.Issuer.Value != sp.IDPMetadata.EntityID {
		retErr.PrivateErr = fmt.Errorf("Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
		return nil, "", retErr
	}

	// decrypt the response
	if req.EncryptedID != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(rawRequestBuf); err != nil {
			retErr.PrivateErr = err
			return nil, "", retErr
		}

		if err := sp.validateSigned(doc.Root()); err != nil {
			retErr.PrivateErr = err
			return nil, "", retErr
		}

		el := doc.FindElement("//EncryptedID/EncryptedData")
		plaintextNameID, err := xmlenc.Decrypt(sp.Key, el)
		if err != nil {
			retErr.PrivateErr = fmt.Errorf("failed to decrypt request: %s", err)
			return nil, "", retErr
		}
		retErr.Request = string(plaintextNameID)

		doc = etree.NewDocument()
		if err := doc.ReadFromBytes(plaintextNameID); err != nil {
			retErr.PrivateErr = fmt.Errorf("cannot parse plaintext request %v", err)
			return nil, "", retErr
		}
		nameID = &NameID{}
		if err := xml.Unmarshal(plaintextNameID, nameID); err != nil {
			retErr.PrivateErr = err
			return nil, "", retErr
		}

	}
	return nameID, req.ID, nil
}

// validateAssertion checks that the conditions specified in assertion match
// the requirements to accept. If validation fails, it returns an error describing
// the failure. (The digital signature on the assertion is not checked -- this
// should be done before calling this function).
func (sp *ServiceProvider) validateAssertion(assertion *Assertion, possibleRequestIDs []string, now time.Time) error {
	if assertion.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("expired on %s", assertion.IssueInstant.Add(MaxIssueDelay))
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return fmt.Errorf("issuer is not %q", sp.IDPMetadata.EntityID)
	}
	for _, subjectConfirmation := range assertion.Subject.SubjectConfirmations {
		requestIDvalid := false
		for _, possibleRequestID := range possibleRequestIDs {
			if subjectConfirmation.SubjectConfirmationData.InResponseTo == possibleRequestID {
				requestIDvalid = true
				break
			}
		}
		if !requestIDvalid {
			return fmt.Errorf("SubjectConfirmation one of the possible request IDs (%v)", possibleRequestIDs)
		}
		if subjectConfirmation.SubjectConfirmationData.Recipient != sp.AcsURL.String() {
			return fmt.Errorf("SubjectConfirmation Recipient is not %s", sp.AcsURL.String())
		}
		if subjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Add(MaxClockSkew).Before(now) {
			return fmt.Errorf("SubjectConfirmationData is expired")
		}
	}
	if assertion.Conditions.NotBefore.Add(-MaxClockSkew).After(now) {
		return fmt.Errorf("Conditions is not yet valid")
	}
	if assertion.Conditions.NotOnOrAfter.Add(MaxClockSkew).Before(now) {
		return fmt.Errorf("Conditions is expired")
	}

	audienceRestrictionsValid := false
	for _, audienceRestriction := range assertion.Conditions.AudienceRestrictions {
		if audienceRestriction.Audience.Value == sp.MetadataURL.String() {
			audienceRestrictionsValid = true
		}
	}
	if !audienceRestrictionsValid {
		return fmt.Errorf("Conditions AudienceRestriction does not contain %q", sp.MetadataURL.String())
	}
	return nil
}

func findChild(parentEl *etree.Element, childNS string, childTag string) (*etree.Element, error) {
	for _, childEl := range parentEl.ChildElements() {
		if childEl.Tag != childTag {
			continue
		}

		ctx, err := etreeutils.NSBuildParentContext(childEl)
		if err != nil {
			return nil, err
		}
		ctx, err = ctx.SubContext(childEl)
		if err != nil {
			return nil, err
		}

		ns, err := ctx.LookupPrefix(childEl.Space)
		if err != nil {
			return nil, fmt.Errorf("[%s]:%s cannot find prefix %s: %v", childNS, childTag, childEl.Space, err)
		}
		if ns != childNS {
			continue
		}

		return childEl, nil
	}
	return nil, nil
}

// validateSigned returns a nil error iff each of the signatures on the Response and Assertion elements
// are valid and there is at least one signature.
func (sp *ServiceProvider) validateSigned(responseEl *etree.Element) error {
	haveSignature := false

	// Some SAML responses have the signature on the Response object, and some on the Assertion
	// object, and some on both. We will require that at least one signature be present and that
	// all signatures be valid
	sigEl, err := findChild(responseEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}
	if sigEl != nil {
		if err = sp.validateSignature(responseEl); err != nil {
			return fmt.Errorf("cannot validate signature on Response: %v", err)
		}
		haveSignature = true
	}

	assertionEl, err := findChild(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	if err != nil {
		return err
	}
	if assertionEl != nil {
		sigEl, err := findChild(assertionEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
		if err != nil {
			return err
		}
		if sigEl != nil {
			if err = sp.validateSignature(assertionEl); err != nil {
				return fmt.Errorf("cannot validate signature on Response: %v", err)
			}
			haveSignature = true
		}
	}

	if !haveSignature {
		return errors.New("either the Response or Assertion must be signed")
	}
	return nil
}

// validateSignature returns nill iff the Signature embedded in the element is valid
func (sp *ServiceProvider) validateSignature(el *etree.Element) error {
	cert, err := sp.getIDPSigningCert()
	if err != nil {
		return err
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if Clock != nil {
		validationContext.Clock = Clock
	}

	// Some SAML responses contain a RSAKeyValue element. One of two things is happening here:
	//
	// (1) We're getting something signed by a key we already know about -- the public key
	//     of the signing cert provided in the metadata.
	// (2) We're getting something signed by a key we *don't* know about, and which we have
	//     no ability to verify.
	//
	// The best course of action is to just remove the KeyInfo so that dsig falls back to
	// verifying against the public key provided in the metadata.
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if sigEl := el.FindElement("./Signature"); sigEl != nil {
			if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
				sigEl.RemoveChild(keyInfo)
			}
		}
	}

	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return err
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return err
	}
	el, err = etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return err
	}

	_, err = validationContext.Validate(el)
	return err
}

// MakeLogoutResponse produces a new LogoutResponse object for idpURL in response to inResponseTo ID
func (sp *ServiceProvider) MakeLogoutResponse(inResponseTo string, idpURL string) (*LogoutResponse, error) {
	resp := LogoutResponse{
		Destination:  idpURL,
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: inResponseTo,
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: &Issuer{
			Value: sp.MetadataURL.String(),
		},
		Status: Status{
			StatusCode: StatusCode{
				Value: StatusSuccess,
			},
		},
	}
	return &resp, nil
}

// Redirect returns a URL suitable for using the redirect binding with the request
func (resp *LogoutResponse) Redirect() *url.URL {
	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	if _, err := doc.WriteTo(w2); err != nil {
		panic(err)
	}
	w2.Close()
	w1.Close()

	rv, _ := url.Parse(resp.Destination)

	query := rv.Query()
	query.Set("SAMLResponse", string(w.Bytes()))

	rv.RawQuery = query.Encode()

	return rv
}

// MemoryX509KeyStore is used for the dsig NewDefaultSigningContext
type MemoryX509KeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

// GetKeyPair return the private key and cert. Fullfils the dsig.X509KeyStore interface
func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

// SigningContext returns a dsig.SigningContext which can sign a LogoutResponse
func (sp *ServiceProvider) SigningContext() *dsig.SigningContext {
	sp.signingContextMu.RLock()
	signingContext := sp.signingContext
	sp.signingContextMu.RUnlock()

	if signingContext != nil {
		return signingContext
	}

	sp.signingContextMu.Lock()
	defer sp.signingContextMu.Unlock()
	sp.signingContext = dsig.NewDefaultSigningContext(&MemoryX509KeyStore{sp.Key, sp.Certificate.Raw})
	sp.signingContext.SetSignatureMethod(dsig.RSASHA1SignatureMethod)
	return sp.signingContext
}
