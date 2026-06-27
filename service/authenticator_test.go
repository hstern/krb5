package service

import (
	"testing"

	"github.com/hstern/x/identity"
	"github.com/stretchr/testify/assert"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	// s := new(SPNEGOAuthenticator).
	var s KRB5BasicAuthenticator

	a := new(identity.Authenticator)
	assert.Implements(t, a, s)
}
