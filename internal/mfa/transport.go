package mfa

import (
	"fmt"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

// OpaqueTransportError refuses transports whose byte stream cannot carry an
// interactive MFA challenge. Configuring MFA must never silently disable it.
func OpaqueTransportError(user models.User, transport string) error {
	switch {
	case user.PasswordHash != "":
		return fmt.Errorf("%s is unavailable when password MFA is enabled on your account", transport)
	case user.TOTPEnabled:
		return fmt.Errorf("%s is unavailable when TOTP MFA is enabled on your account", transport)
	case config.Get().RequireMFA.Enabled:
		return fmt.Errorf("%s is unavailable while global MFA enforcement is enabled", transport)
	default:
		return nil
	}
}
