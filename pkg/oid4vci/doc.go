// Package oid4vci implements this service's own OID4VCI Credential Issuer,
// fronting Vault: its own discovery document, /authorize, /token, and
// /userinfo endpoints (its OAuth 2.0 Authorization Server role), delegating
// authentication (Vault's userpass auth method) and claims (Vault's KV v2
// engine) to Vault underneath, and signing id_tokens itself via Vault's
// transit secrets engine.
//
// This exists because Vault's own OIDC Identity Provider issues a
// capability-less access token usable only at its own /userinfo — never for
// KV reads or anything else — and has no path to RFC 9396
// authorization_details support. See issue #17 for the full rationale.
package oid4vci
