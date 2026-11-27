package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// NewVcCmd builds the vc command, grouping verifiable-credential
// operations. With no subcommand it displays help.
func NewVcCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vc",
		Short: "Manage verifiable credentials",
	}
	cmd.AddCommand(NewVcGetCmd())
	return cmd
}

// VcGetOpts ===============================================================================================================

// VcGetOpts holds vc get's flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
type VcGetOpts struct {
	RootOpts
	CredentialIdentifier      string
	CredentialConfigurationId string
	Key                       string
	User                      string
}

// NewVcGetOpts constructs a VcGetOpts.
func NewVcGetOpts() *VcGetOpts {
	return &VcGetOpts{}
}

// Run fetches a credential for o.User against o.Issuer, naming it by
// o.CredentialIdentifier (from authorization_details captured at login) or
// o.CredentialConfigurationId, proving possession of a holder key, and
// stores the result in the holder.
func (o *VcGetOpts) Run() error {
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	vc, err := w.GetCredential(o.Key, o.CredentialIdentifier)
	if err != nil {
		return err
	}

	return printCredential(vc)
}

// NewVcGetCmd builds the vc get command.
func NewVcGetCmd() *cobra.Command {
	opts := NewVcGetOpts()
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Fetch a verifiable credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.CredentialIdentifier, "credential-identifier", "", "Credential identifier from authorization_details")
	cmd.Flags().StringVar(&opts.Key, "key", "", "Holder key name (defaults to the connection's default key)")
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (default: the issuer's default user)")
	_ = cmd.RegisterFlagCompletionFunc("credential-identifier", completeCredentialIdentifier)
	_ = cmd.RegisterFlagCompletionFunc("key", completeHolderKey)
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
	return cmd
}

// Functions -----------------------------------------------------------------------------------------------------------

// printCredential pretty-prints vc's decoded JWT header and payload, and —
// for an SD-JWT VC — each disclosure it carries, decoded to the
// [salt, claim name, claim value] array it discloses. Signatures aren't
// verified: this is for human inspection, not trust.
func printCredential(vc string) error {
	parts := strings.Split(vc, "~")

	header, payload, err := decodeJWT(parts[0])
	if err != nil {
		return err
	}
	fmt.Println("Header:")
	if err := printJSON(header); err != nil {
		return err
	}
	fmt.Println("Payload:")
	if err := printJSON(payload); err != nil {
		return err
	}

	for _, disclosure := range parts[1:] {
		if disclosure == "" {
			continue
		}
		decoded, err := decodeDisclosure(disclosure)
		if err != nil {
			return err
		}
		fmt.Printf("%s => %s\n", formatDisclosure(decoded), digestDisclosure(disclosure))
	}
	return nil
}

// digestDisclosure returns encoded's SD-JWT digest: base64url(sha256(ASCII(encoded))).
func digestDisclosure(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// formatDisclosure renders a decoded [salt, claim name, claim value] array
// as ["salt", "name", value], string values printed bare rather than
// JSON-quoted — matching scripts/keycloak-functions' decode_vc, so
// Keycloak- and Vault-issued credentials inspect identically.
func formatDisclosure(arr []any) string {
	salt, name, value := arr[0], arr[1], arr[2]
	val, ok := value.(string)
	if !ok {
		data, _ := json.Marshal(value)
		val = string(data)
	}
	return fmt.Sprintf("[%q, %q, %s]", salt, name, val)
}

// decodeDisclosure decodes an SD-JWT disclosure segment to the
// [salt, claim name, claim value] array it discloses.
func decodeDisclosure(encoded string) ([]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode disclosure: %w", err)
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("decode disclosure: %w", err)
	}
	return arr, nil
}

// decodeJWT decodes token's header and payload segments, without verifying
// its signature.
func decodeJWT(token string) (header, payload map[string]any, err error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, nil, fmt.Errorf("decode JWT: expected 3 segments, got %d", len(segments))
	}
	if header, err = decodeJSONSegment(segments[0]); err != nil {
		return nil, nil, fmt.Errorf("decode JWT header: %w", err)
	}
	if payload, err = decodeJSONSegment(segments[1]); err != nil {
		return nil, nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	return header, payload, nil
}

// decodeJSONSegment base64url-decodes and JSON-unmarshals one JWT segment.
func decodeJSONSegment(segment string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
