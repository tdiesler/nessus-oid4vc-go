package vault

import "fmt"

// Entity ===============================================================================================================

// Entity is a Vault Identity entity's externally-visible properties.
type Entity struct {
	Id       string
	Name     string
	Metadata map[string]string
}

func NewEntity(id, name string, metadata map[string]string) *Entity {
	return &Entity{
		Id:       id,
		Name:     name,
		Metadata: metadata,
	}
}

// EntityAccessor =======================================================================================================

// EntityAccessor accesses Vault's identity entity endpoint.
type EntityAccessor struct {
}

// NewEntityAccessor constructs an EntityAccessor.
func NewEntityAccessor() *EntityAccessor {
	return &EntityAccessor{}
}

// Entity reads the named identity entity's properties, authenticated as
// token — which must be that entity's own token (per Vault's built-in
// default policy's self-read grant), or hold broader identity read access.
func (s *EntityAccessor) Entity(token *AccessToken, name string) (*Entity, error) {

	client, err := NewClient(token.Token)
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Read("identity/entity/name/" + name)
	if err != nil {
		return nil, fmt.Errorf("read identity entity %q: %w", name, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("identity entity %q not found", name)
	}

	id, _ := secret.Data["id"].(string)
	metadata := map[string]string{}
	if raw, ok := secret.Data["metadata"].(map[string]any); ok {
		for k, v := range raw {
			if str, ok := v.(string); ok {
				metadata[k] = str
			}
		}
	}

	return NewEntity(id, name, metadata), nil
}
