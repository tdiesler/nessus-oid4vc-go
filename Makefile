KUBE_CONTEXT := rancher-desktop

run-cli:
	go run ./pkg/cmd/oid4vc

run-server:
	VAULT_ROOT_TOKEN=$$(kubectl --context=$(KUBE_CONTEXT) get secret vault-secret -o jsonpath='{.data.ROOT_TOKEN}' | base64 -d) \
	go run ./pkg/cmd/oid4vc run-server

upgrade:
	helm upgrade --kube-context=$(KUBE_CONTEXT) --install nessus-vault ./helm -f ./helm/values-vault.yaml
