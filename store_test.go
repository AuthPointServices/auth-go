package auth_test

import (
	"testing"

	auth "github.com/AuthPointServices/auth-go"
	"github.com/AuthPointServices/auth-go/storetest"
)

func TestMemoryStore(t *testing.T) {
	storetest.Run(t, func(*testing.T) auth.Store { return auth.NewMemoryStore() })
}
