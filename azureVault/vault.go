package azureVault

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/matryer/try"
	"github.com/pkg/errors"
)

const (
	apiVersion = "2016-10-01"
)

type authenticationResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
}

type keyVaultAttributesResponse struct {
	Enabled       bool   `json:"enabled"`
	Created       int    `json:"created"`
	Updated       int    `json:"updated"`
	RecoveryLevel string `json:"recoverylevel"`
}

type keyVaultResponse struct {
	Value      string                     `json:"value"`
	ID         string                     `json:"id"`
	Attributes keyVaultAttributesResponse `json:"attributes"`
}

// RenewAccessToken will renew accesstoken for azure vault
func (v *Vault) RenewAccessToken() (err error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.accessToken, err = v.getAccessTokenWithRetry()
	return err
}

// GetValues is same as GetValue but for multiple values
func (v Vault) GetValues(keys []string, results []*string) error {
	if len(keys) != len(results) {
		return errors.New("number of keys and results must be equal")
	}

	for i, key := range keys {
		value, err := v.GetValue(key)
		if err != nil {
			return errors.Wrap(err, "failed to get value for key "+key)
		}
		*(results[i]) = value
	}
	return nil
}

// GetValue will return value for key from azure Vault.
func (v Vault) GetValue(key string) (string, error) {
	var value string

	err := try.Do(func(attempt int) (bool, error) {
		var err error
		value, err = v.getKeyVaultValue(key) // err is already logged inside internal function
		return attempt < 5, err
	})

	if err != nil {
		if try.IsMaxRetries(err) {
			return "", err
		}
		return "", errors.Wrap(err, "failed to get value")
	}
	return value, nil
}

func (v Vault) getKeyVaultValue(uri string) (string, error) {
	request, err := http.NewRequest("GET", uri+v.apiVersion, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create request")
	}

	request.Header.Set("Authorization", "Bearer "+v.accessToken)

	keyVaultHTTPResponse, err := v.cli.Do(request)
	if err != nil {
		return "", errors.Wrap(err, "failed execute request")
	}

	if keyVaultHTTPResponse.StatusCode != http.StatusOK {
		v.logger.Infof("error requesting secret from key vault (StatusCode: %d)", keyVaultHTTPResponse.StatusCode)

		switch keyVaultHTTPResponse.StatusCode {
		case http.StatusForbidden:
			return "", errors.Wrap(err, "application is not authorized by Azure Active Directory")
		case http.StatusUnauthorized:
			err = v.RenewAccessToken()
			if err != nil {
				return "", errors.Wrap(err, "failed to renew access token")
			}
		}
	}

	kvResponse := &keyVaultResponse{}
	if err := json.NewDecoder(keyVaultHTTPResponse.Body).Decode(kvResponse); err != nil {
		return "", errors.Wrap(err, "failed to deserialize response body")
	}

	return kvResponse.Value, nil
}

func (v Vault) getAccessTokenWithRetry() (string, error) {
	var token string

	err := try.Do(func(attempt int) (bool, error) {
		var err error
		token, err = v.getAccessToken()
		if err != nil {
			v.logger.Info(errors.Wrapf(err, "failed to get access token on %d attempt", attempt))
			time.Sleep(500 * time.Millisecond) // retry delay
		}
		return attempt < 5, err
	})

	if err != nil {
		if try.IsMaxRetries(err) {
			return "", err
		}
		return "", errors.Wrap(err, "failed to get access token")
	}
	return token, nil
}

func (v Vault) getAccessToken() (string, error) {
	resp, err := v.cli.Do(v.authRequest)
	if err != nil {
		return "", errors.Wrap(err, "failed to execute request")
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.Wrapf(err, "error requesting access token from active directory (StatusCode: %d)", resp.StatusCode)
	}

	authRespData := &authenticationResponse{}
	if err := json.NewDecoder(resp.Body).Decode(authRespData); err != nil {
		return "", errors.Wrap(err, "failed to deserialize response body")
	}

	if len(authRespData.AccessToken) == 0 {
		return "", ErrEmptyAccessToken
	}

	return authRespData.AccessToken, nil
}
