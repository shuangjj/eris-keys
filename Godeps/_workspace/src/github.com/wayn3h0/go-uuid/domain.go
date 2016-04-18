package uuid

import (
	"github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/wayn3h0/go-uuid/internal/dcesecurity"
)

// Domain represents the identifier for a local domain
type Domain byte

// Domains.
const (
	DomainUser  = Domain(dcesecurity.User)  // POSIX UID domain
	DomainGroup = Domain(dcesecurity.Group) // POSIX GID domain
)
