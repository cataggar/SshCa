# Rotating the SSH Certificate Authority

CA rotation requires a trust-overlap period. Creating a Key Vault key version
does not update server trust or the active issuance version automatically.

1. Create exactly one new version:

   ```sh
   sshca ca rotate \
     --vault-url "https://example.vault.azure.net" \
     --name ssh-user-ca
   ```

2. Export the new version's public key:

   ```sh
   sshca ca public-key \
     --vault-url "https://example.vault.azure.net" \
     --name ssh-user-ca \
     --version NEW_VERSION \
     > new-ca.pub
   ```

3. Add both old and new CA public-key lines to every server's
   `TrustedUserCAKeys` file.
4. Validate and reload `sshd`, then confirm the new trust file is deployed to
   every server.
5. Change the active issuance version explicitly:

   ```sh
   export SSHCA_ACTIVE_KEY_VERSION=NEW_VERSION
   ```

   Production services should update their managed configuration rather than
   relying on a shell environment variable.
6. Wait at least the maximum certificate TTL plus the clock-skew allowance.
   With the default policy this overlap is at least 8 hours and 60 seconds.
7. Remove the old CA public-key line from every server, validate the
   configuration, and reload `sshd`.
8. Disable the old Key Vault key version only after the trust overlap is
   complete and no server relies on it.

Do not use `--latest` for production issuance. Pinning the version ensures the
public key embedded in each certificate is the same version used for the Key
Vault signing operation.
