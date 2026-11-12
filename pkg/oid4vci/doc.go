// Package oid4vci implements the OID4VCI issuance flow as plain Go
// services: direct holder authentication, credential offer creation
// (including delegated pre-authorized-code minting, see issue #13),
// pre-authorized-code redemption, and credential issuance. HTTP endpoints
// are a later pass once these are proven out.
package oid4vci
