// Package wallet models a holder wallet's local, on-disk state: the OIDC
// issuers it can authenticate against — Keycloak realms and Vault OIDC
// providers — and the sessions and credentials obtained from each.
//
// State is split one JSON file per issuer kind (wallet.vault.json,
// wallet.keycloak.json, ...) rather than a single shared file, so each
// backend's own tooling — this package's Vault login path,
// scripts/keycloak-setup's Java-CLI-to-Issuer transform — can write its
// file without clobbering the other's.
package wallet
