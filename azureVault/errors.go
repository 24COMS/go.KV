package azureVault

import "errors"

var (
	// ErrEmptyParam will be returned if some of the params are empty
	ErrEmptyParam = errors.New("some of params are empty")
	// ErrEmptyAccessToken will be returned if access token is empty
	ErrEmptyAccessToken = errors.New("got empty access token from response")
)
