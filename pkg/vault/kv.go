package vault

import (
	"context"
	"fmt"
)

const (
	SecretsPathOffers   = "offers"
	SecretsPathSubjects = "subjects"
)

// KeyValueAccessor ====================================================================================================

// KeyValueAccessor accesses a subject's claims in Vault's KV v2 secrets engine.
type KeyValueAccessor struct {
}

// NewKeyValueAccessor constructs a KeyValueAccessor.
func NewKeyValueAccessor() *KeyValueAccessor {
	return &KeyValueAccessor{}
}

// ReadSubjectsKeyValueClaims reads the named subject's claims from secret/subjects/{name},
// authenticated as token — which must be that subject's own token (per the
// subject-self policy), or hold broader read access.
func (s *KeyValueAccessor) ReadSubjectsKeyValueClaims(token *AccessToken, alias string) (map[string]any, error) {
	return s.ReadKeyValueClaims(token, SecretsPathSubjects, alias)
}

// ReadKeyValueClaims reads alias's data from secret/{path}/{alias} (e.g.
// SecretsPathOffers or SecretsPathSubjects), authenticated as token — which
// must hold read access to that path (e.g. alias's own subject-self policy
// for their own path, or an issuer's broader grant for someone else's).
func (s *KeyValueAccessor) ReadKeyValueClaims(token *AccessToken, path, alias string) (map[string]any, error) {
	client, err := NewClient(token.Token)
	if err != nil {
		return nil, err
	}

	kv, err := client.KVv2("secret").Get(context.Background(), path+"/"+alias)
	if err != nil {
		return nil, fmt.Errorf("read %s/%s: %w", path, alias, err)
	}
	return kv.Data, nil
}

// WriteKeyValueClaims writes data to secret/{path}/{alias}, authenticated as
// token — which must hold write access to that path (e.g. an issuer's
// per-subject subject-{path}-write-{alias} policy), not necessarily read
// access to it.
func (s *KeyValueAccessor) WriteKeyValueClaims(token *AccessToken, path, alias string, data map[string]any) error {
	client, err := NewClient(token.Token)
	if err != nil {
		return err
	}

	_, err = client.KVv2("secret").Put(context.Background(), path+"/"+alias, data)
	if err != nil {
		return fmt.Errorf("write %s/%s: %w", path, alias, err)
	}
	return nil
}
