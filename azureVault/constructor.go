package azureVault

import (
	"24coms-dialog/KV"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/24COMS/go.isempty"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Vault is client for Azure key/value storage
type Vault struct {
	cli         *http.Client
	authRequest *http.Request
	accessToken string // Cached access token, will be regenerated on 401 status code

	apiVersion string
	logger     logrus.FieldLogger
	mu         *sync.Mutex
}

// New is constructor for new Vault which will set required params and get new access token
func New(logger logrus.FieldLogger, clientID, clientSecret, tenant string) (KV.Store, error) {
	if isEmpty.Values(clientID, clientSecret, tenant) {
		return nil, ErrEmptyParam
	}

	authData := url.Values{}
	authData.Set("grant_type", "client_credentials")
	authData.Set("resource", "https://vault.azure.net")
	authData.Set("client_id", clientID)
	authData.Set("client_secret", clientSecret)

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenant),
		strings.NewReader(authData.Encode()),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new auth request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	v := Vault{
		cli:         &http.Client{},
		authRequest: req,
		apiVersion:  "?api-version=" + apiVersion, // TODO: use url.URL

		logger: logger,
		mu:     &sync.Mutex{},
	}

	err = v.RenewAccessToken()
	if err != nil {
		return nil, err
	}

	return &v, nil
}
