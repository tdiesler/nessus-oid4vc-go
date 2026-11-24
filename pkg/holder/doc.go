// Package holder models a holder holder's local, on-disk state: the OIDC
// issuers it can authenticate against — Keycloak realms and Vault OIDC
// providers — and the sessions and credentials obtained from each. Wallet
// is the handle CLI commands operate on: one issuer and user resolved from
// that state, exposing the holder's operations (login, logout, key
// creation, credential issuance) as methods.
//
// State is split one JSON file per issuer (holder.<alias>.json) rather
// than a single shared file, so each backend's own tooling — this
// package's Vault login path, scripts/keycloak-setup's Java-CLI-to-Issuer
// transform — can write its file without clobbering another issuer's.
package holder
