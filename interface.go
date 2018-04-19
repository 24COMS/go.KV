package KV

// Store describes common interface for any KV storage in application
type Store interface {
	RenewAccessToken() (err error)
	GetValue(key string) (string, error)
	GetValues(keys []string, results []*string) error
}
