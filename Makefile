KUBE_CONTEXT := rancher-desktop

upgrade:
	helm upgrade --kube-context=$(KUBE_CONTEXT) --install nessus-vault ./helm -f ./helm/values-vault.yaml

vault-setup:
	scripts/vault-setup
