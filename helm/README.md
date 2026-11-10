# Helm Deployment

## Prerequisites

### Kubernetes cluster

A local [Rancher Desktop](https://rancherdesktop.io/) (K3s) cluster.

### Secrets

Create the required secret before deploying. The root token value is
arbitrary — Vault dev mode just adopts whatever you give it — so generate a
random one:

```bash
VAULT_ROOT_TOKEN=$(openssl rand -hex 16)
kubectl --context=rancher-desktop delete secret vault-secret --ignore-not-found
kubectl --context=rancher-desktop create secret generic vault-secret \
  --from-literal=ROOT_TOKEN=$VAULT_ROOT_TOKEN
echo "VAULT_ROOT_TOKEN=$VAULT_ROOT_TOKEN"
```

Keep a note of the printed token — you'll need it to log in below.

## Deploy

```bash
make upgrade
```

which runs:

```bash
helm upgrade --install nessus-vault ./helm -f ./helm/values-vault.yaml
```

## Services

| Service | In-cluster      | NodePort           |
|---------|-----------------|---------------------|
| Vault   | `vault:8200`    | `localhost:30820`  |

Vault UI/API: http://localhost:30820

Login with the root token you generated above:

```bash
export VAULT_ADDR=http://localhost:30820
vault login $VAULT_ROOT_TOKEN
```

This Vault runs in **dev mode**: storage is in-memory, so all data is lost
on pod restart. That's expected for this POC — it is not a production
deployment pattern.

## Setup

```bash
make vault-setup
```

Runs `scripts/vault-setup`, which configures everything this project needs
on top of the raw Vault instance. 

The script is **fully idempotent**: it disables and re-enables everything it
owns before recreating it, so re-running it always produces the same
starting state.

## Teardown

```bash
helm uninstall nessus-vault
```
