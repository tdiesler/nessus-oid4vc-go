package common

import (
	"os"
)

// Fixed by scripts/vault-setup's holder persona.
const (
	UserAlice    = "alice"
	UserMax      = "max"
	UserPassword = "password"
)

// FileSnapshot ================================================================================================================

// FileSnapshot captures a file's content so a test can mutate it and later
// put it back, leaving no lasting effect on real on-disk state (e.g. a
// holder file under .config/) that other tests or manual runs also use.
type FileSnapshot struct {
	path    string
	data    []byte
	existed bool
}

// NewFileSnapshot captures path's current content. path not existing yet
// is itself a valid thing to capture — Restore then removes it again.
func NewFileSnapshot(path string) (*FileSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &FileSnapshot{path: path}, nil
		}
		return nil, err
	}
	return &FileSnapshot{path: path, data: data, existed: true}, nil
}

// Restore writes path back to its original content, or removes it if
// it didn't exist when s was captured.
func (s *FileSnapshot) Restore() error {
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(s.path, s.data, 0o600)
}

// Functions ---------------------------------------------------------------------------------------------------------
