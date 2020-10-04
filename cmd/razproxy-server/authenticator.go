package main

type authenticator map[string]string

func (auth authenticator) Valid(user, password string) bool {
	pw, ok := auth[user]
	return ok && pw == password
}
