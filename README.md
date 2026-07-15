# SshCA

[![Zig build and test](https://github.com/cataggar/SshCa/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/cataggar/SshCa/actions/workflows/build-and-test.yml)

SshCA is a Zig 0.16 OpenSSH user certificate authority backed by a
non-exportable Azure Key Vault RSA key. It issues short-lived RSA or Ed25519
user certificates without loading CA private-key material into the process or
copying it to SSH servers.

## Build

Install Zig 0.16.0, OpenSSL development files, and `pkg-config`, then run:

```sh
zig build
zig build test
```

The CLI is written to:

```text
zig-out/bin/sshca
```

## Azure authentication

The CLI uses `DefaultAzureCredential`, supporting environment credentials,
workload identity, managed identity, and Azure CLI authentication.

For local development:

```sh
az login
az account set --subscription SUBSCRIPTION_ID
az account show --query '{name:name,id:id}' --output table
export SSHCA_AZURE_CREDENTIAL=azure-cli
```

The credential mode defaults to `default`, which uses
`DefaultAzureCredential`. Set it to `azure-cli` only for an existing Azure CLI
session, including the protected live-test workflow. Do not pass tokens or
client secrets on the `sshca` command line.

The examples use the public Azure cloud. Select `--cloud government` or
`--cloud china` for sovereign clouds; this changes both the trusted Key Vault
DNS suffix and token scope. When using Azure CLI credentials, select the
matching CLI cloud before signing in:

```sh
az cloud set --name AzureUSGovernment # --cloud government
az cloud set --name AzureChinaCloud    # --cloud china
az login
```

## Provision the CA key

The provisioning identity needs key create/read permissions, such as
`Key Vault Crypto Officer` during initial setup.

```sh
sshca ca ensure \
  --vault-url "https://example.vault.azure.net" \
  --name ssh-user-ca
```

Defaults:

- non-exportable RSA
- 3072 bits
- only `sign` and `verify` operations
- enabled key

Supported sizes are 2048, 3072, and 4096. Use `--hsm` only with a Premium
Key Vault:

```sh
sshca ca ensure \
  --vault-url "https://example.vault.azure.net" \
  --name ssh-user-ca \
  --bits 4096 \
  --hsm
```

`ensure` reuses a compatible existing key. It creates a version only after a
404 response. `ca rotate` is the only command that deliberately creates a new
version.

## Configure server trust

Export an explicit version:

```sh
sshca ca public-key \
  --vault-url "https://example.vault.azure.net" \
  --name ssh-user-ca \
  --version KEY_VERSION \
  > trusted-user-ca-keys
```

Install that public file on each server and configure:

```text
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys
```

The plain `ca public-key` output is appropriate for `TrustedUserCAKeys`.
`--cert-authority` instead emits the marker used in an individual
`authorized_keys` entry.

See [docs/server-trust.md](docs/server-trust.md) for ownership, permissions,
principals, safe reload, and client configuration.

## Issue a certificate

Use the exact version printed by `ca ensure`:

```sh
sshca sign \
  --vault-url "https://example.vault.azure.net" \
  --name ssh-user-ca \
  --version KEY_VERSION \
  --subject-key ~/.ssh/id_ed25519.pub \
  --key-id alice@example \
  --principal alice
```

The default TTL is one hour, with a maximum of eight hours. The default output
is `~/.ssh/id_ed25519-cert.pub`, which OpenSSH discovers next to the matching
private key:

```sh
ssh -i ~/.ssh/id_ed25519 alice@server
```

The active version can also be supplied through:

```sh
export SSHCA_ACTIVE_KEY_VERSION=KEY_VERSION
```

`--latest` is development-only. Production issuance must pin an explicit
version so the embedded CA public key and Key Vault signing operation always
refer to the same key version.

Useful restrictions and extensions:

```text
--ttl SECONDS
--principal NAME                 repeatable
--profile interactive|none
--force-command COMMAND
--source-address CIDR[,CIDR...]
--permit-agent-forwarding
--permit-port-forwarding
--permit-pty
--permit-user-rc
--permit-x11-forwarding
--comment TEXT
```

Source-address CIDRs must use canonical network addresses with zero host bits.

## Managed identity and production issuance

An administrative operator may use `ca ensure` and `ca rotate`. A production
issuer should use a separate managed or workload identity with a custom role
containing only:

```text
Microsoft.KeyVault/vaults/keys/read
Microsoft.KeyVault/vaults/keys/sign/action
```

Do not grant the production issuer broad administrative roles or the built-in
`Key Vault Crypto User` role, which includes operations not required for SSH
certificate issuance. SSH clients and servers need no Azure permissions.

GitHub Actions can use a user-assigned managed identity with a federated
credential whose subject is
`repo:OWNER/REPOSITORY:environment:ENVIRONMENT`. This setup uses Azure Resource
Manager and does not require Microsoft Graph application-registration access.
If the tenant custom-role quota prevents creating the read/sign-only role,
`Key Vault Crypto User` may be used temporarily at the individual test-vault
scope, but it must be replaced before treating the workflow identity as
least-privileged production configuration.

## Rotation

Create a new version explicitly:

```sh
sshca ca rotate \
  --vault-url "https://example.vault.azure.net" \
  --name ssh-user-ca
```

Servers must trust both old and new CA public keys before issuance switches to
the new version. See [docs/key-rotation.md](docs/key-rotation.md) for the
required overlap sequence.

## Testing

```sh
zig build test
zig build integration-test
zig build integration-test -Dwith-sshd=true
```

The credentialed live test is opt-in:

```sh
export SSHCA_TEST_VAULT_URL="https://example.vault.azure.net"
export SSHCA_TEST_KEY_NAME="ssh-user-ca"
export SSHCA_TEST_KEY_VERSION="EXPLICIT_VERSION"
export SSHCA_TEST_CLOUD="public"
zig build live-azure-test -Dlive-azure=true
```

It reads the pre-provisioned test key version, exports its public key, signs
through Key Vault, validates the certificate with OpenSSH, and completes RSA
and Ed25519 logins against an isolated, digest-pinned `sshd` container. It
never creates, rotates, updates, disables, or deletes a key.

## Library

`src/root.zig` exports bounded OpenSSH public-key parsing, PEM parsing,
certificate serialization, issuance policy, signer interfaces, and the Azure
Key Vault adapter. The administrative CLI is suitable for setup and manual
issuance; production systems should expose a separately authenticated service
that calls the library with a least-privileged workload identity.

## License

MIT. The project retains the original 2025-2026 Dave Curylo attribution in
[LICENSE](LICENSE).
