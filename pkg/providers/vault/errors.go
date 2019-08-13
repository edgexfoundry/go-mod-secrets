package vault

import "fmt"

// ErrCaRootCert error when the provided CA Root certificate is invalid.
type ErrCaRootCert struct {
	path        string
	description string
}

func (e ErrCaRootCert) Error() string {
	return fmt.Sprintf("Unable to use the certificate '%s': %s", e.path, e.description)
}
