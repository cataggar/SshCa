# Trusting the SSH User Certificate Authority

Export the plain CA public key. Do not use `--cert-authority` for a
`TrustedUserCAKeys` file.

```sh
sshca ca public-key \
  --vault-url "https://example.vault.azure.net" \
  --name ssh-user-ca \
  --version KEY_VERSION \
  > trusted-user-ca-keys
```

Install the file on each server:

```sh
sudo install -o root -g root -m 0644 \
  trusted-user-ca-keys \
  /etc/ssh/trusted-user-ca-keys
```

Add this directive to `sshd_config`:

```text
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys
```

The file contains public material only. The Key Vault CA private key is never
copied to an SSH server.

Validate the complete server configuration before reloading it:

```sh
sudo sshd -t
sudo systemctl reload sshd
```

Use the platform's service name if it differs, such as `ssh` instead of
`sshd`. Keep an existing administrative session open until a new
certificate-authenticated session succeeds.

## Principals

Without an `AuthorizedPrincipalsFile`, a user certificate must contain the
target Unix account name as a principal. For example, a certificate used for
`alice@server` normally needs `--principal alice`.

For an explicit authorization mapping:

```text
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

Each principals file must be owned by root or the target account and must not
be writable by group or others. Keep these files independent from
`authorized_keys`; certificate authentication does not require copying a user
public key to the server.

## Client use

Save the certificate next to its private key using OpenSSH's conventional
name:

```text
~/.ssh/id_ed25519
~/.ssh/id_ed25519-cert.pub
```

OpenSSH discovers that certificate automatically:

```sh
ssh -i ~/.ssh/id_ed25519 alice@server
```

For a certificate stored elsewhere, select it explicitly:

```sh
ssh \
  -i ~/.ssh/id_ed25519 \
  -o CertificateFile=~/certificates/alice-cert.pub \
  alice@server
```
