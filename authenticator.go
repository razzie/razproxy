package razproxy

// Authenticator ...
type Authenticator interface {
	Valid(user, password string) bool
}

// BasicAuthenticator ...
type BasicAuthenticator map[string]string

// Valid ...
func (auth BasicAuthenticator) Valid(user, password string) bool {
	pw, ok := auth[user]
	return ok && pw == password
}
