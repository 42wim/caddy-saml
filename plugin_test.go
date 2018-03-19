package samlplugin

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsAuthorized(t *testing.T) {
	token := &AuthorizationToken{
		Attributes: map[string][]string{
			"uid":      []string{"abc"},
			"ounumber": []string{"81234", "12345"},
			"mail":     []string{"myuser@mail.com", "other@mail.com"},
		},
	}
	acl := []string{"uid abc", "ounumber 5678", "mail blah@blah.com"}
	assert.Equal(t, true, isAuthorized(acl, token))
	acl = []string{"uid abcd", "ounumber 5678", "mail blah@blah.com"}
	assert.Equal(t, false, isAuthorized(acl, token))
	acl = []string{"uid abc", "ounumber 12345", "mail blah@blah.com"}
	assert.Equal(t, true, isAuthorized(acl, token))
	acl = []string{"uid abc", "ounumber 12345", "mail other@blah.com"}
	assert.Equal(t, true, isAuthorized(acl, token))
	acl = []string{"uid abc", "ounumber 12345", "mail other@blah.com"}
}

func TestIsAuthorizedAnd(t *testing.T) {
	token := &AuthorizationToken{
		Attributes: map[string][]string{
			"uid":      []string{"abc"},
			"ounumber": []string{"81234", "12345"},
			"mail":     []string{"myuser@mail.com", "other@mail.com"},
		},
	}
	acl := []string{"uid abc", "ounumber 5678", "mail blah@blah.com", "require-all"}
	assert.Equal(t, false, isAuthorized(acl, token))
	acl = []string{"uid abc", "ounumber 81234", "mail other@mail.com", "require-all"}
	assert.Equal(t, true, isAuthorized(acl, token))
	acl = []string{"uid abc", "ounumber 81234", "mail other@mail.coms", "require-all"}
	assert.Equal(t, false, isAuthorized(acl, token))
	acl = []string{"uid abc", "require-all"}
	assert.Equal(t, true, isAuthorized(acl, token))
}
