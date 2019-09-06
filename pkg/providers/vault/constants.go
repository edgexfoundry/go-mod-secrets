package vault

const (
	// VaultProvider indicates the use of Hashicorp's Vault secret manager as a secret store provider.
	VaultProvider = "vault"

	// VaultToken identifies the access token used for authentication when communicating with Vault.
	VaultToken = "X-Vault-Token"
)
