// Package oid4vci implements the OID4VCI issuance flow as plain Go
// services: Vault client access, credential offer creation (including
// delegated pre-authorized-code minting, see issue #13), pre-authorized-code
// redemption, and credential issuance. HTTP endpoints are a later pass once
// these are proven out. The OAuth 2.0/OIDC client-side flow (browser-driven
// authorization, token exchange, discovery) lives in pkg/oauth.
package oid4vci
