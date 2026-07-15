# Zig 0.16 SSH Certificate Authority and Azure Key Vault Integration Plan

## Overview

Replace the F# implementation on the `zig16` branch with a Zig 0.16 library and CLI that:

- Parses and formats OpenSSH RSA and Ed25519 public keys.
- Builds OpenSSH user certificates with bounded validity periods, principals, critical options, and extensions.
- Signs certificates with an RSA or RSA-HSM key whose private material remains in Azure Key Vault.
- Exports the CA public key in forms suitable for `TrustedUserCAKeys` and `authorized_keys`.
- Produces certificates accepted by OpenSSH and usable for a real SSH login.

The SSH wire-format implementation will be pure Zig. Azure authentication, HTTP, retries, and Key Vault operations will reuse `cataggar/azure-sdk-for-zig`. The `cataggar/openssh` `zig16-no-automake` branch will be a pinned, test-only OpenSSH interoperability oracle, not a runtime dependency.

## Current State Analysis

The repository currently contains an F# library with three main components:

- `SshCA/SshBuffer.fs:28` reads length-prefixed SSH data with truncation and allocation limits; `SshCA/SshBuffer.fs:47` and later overloads write SSH strings and big-endian integers.
- `SshCA/PublicKey.fs:27` defines the public-key abstraction, with RSA and Ed25519 implementations at `SshCA/PublicKey.fs:87` and `SshCA/PublicKey.fs:142`.
- `SshCA/PublicKey.fs:214` parses authorized-key lines, `SshCA/PublicKey.fs:296` parses RSA public-key PEM, and `SshCA/PublicKey.fs:275` formats a `cert-authority` line.
- `SshCA/SshCertificate.fs:62` models certificate inputs, including principals, validity, critical options, and extensions.
- `SshCA/SshCertificate.fs:204` serializes the OpenSSH certificate body, `SshCA/SshCertificate.fs:254` appends an `rsa-sha2-512` signature, and `SshCA/SshCertificate.fs:267` exposes the signing abstraction.
- `SshCATests/SshCertTests.fs:30` and `SshCATests/SshCertTests.fs:88` validate RSA and Ed25519 subject certificates with `ssh-keygen -L`.
- `README.md:36` through `README.md:97` demonstrates Azure Key Vault signing and server trust through `TrustedUserCAKeys`.

Important compatibility and correctness findings:

- The CA is always RSA, even when the subject key is Ed25519.
- Azure Key Vault must receive a locally computed 64-byte SHA-512 digest and sign it with `RS512` (RSA PKCS#1 v1.5 with SHA-512).
- The current helper API stores non-empty critical-option values as plain bytes. OpenSSH encodes values such as `force-command` and `source-address` as a nested SSH string and orders options lexically. The Zig port will implement the OpenSSH encoding rather than preserve this wire-format defect.
- The current async serializer always emits the RSA certificate algorithm at `SshCA/SshCertificate.fs:326`; the Zig port will use one shared serialization path for both subject algorithms.
- The existing tests parse certificate output but do not prove that `sshd` accepts the signature during authentication. The Zig test strategy adds a real SSH login.

## Reference Implementations

### OpenSSH Zig 0.16 build

Use `cataggar/openssh` commit `954c03dd1aef8075ee60ea103e4020213de3e591` from branch `zig16-no-automake`.

Relevant properties:

- `build.zig.zon` requires Zig 0.16.0.
- `build.zig` exposes `ssh-keygen` and the other OpenSSH programs as dependency artifacts.
- `zig build test` wires the upstream C unit tests into the Zig build graph.
- The frozen OpenSSH build configuration is Linux/glibc-specific, so this dependency is limited to Linux integration tests.

### Azure SDK for Zig

Use `cataggar/azure-sdk-for-zig` as the Azure dependency. The inspected baseline is commit `4dc4a182d55a20fd463ed4a3a6fdd673bbfa2191`.

Reusable components already present:

- `sdk/core/identity/default_azure_credential.zig` provides environment, workload identity, managed identity, and Azure CLI credential chaining.
- `sdk/core/http/transport.zig` uses Zig 0.16 `std.http.Client` and preserves authorization headers correctly.
- `sdk/core/http/pipeline.zig` provides `BearerTokenAuthPolicy`, token caching, retries, telemetry, and request IDs.
- `sdk/keyvault/keys/root.zig` has preliminary `KeyClient` and `CryptographyClient` types.

Required SDK fixes are included as a phase below because the current Key Vault clients ignore the supplied credential, do not expose RSA `n` and `e`, create only a minimal `{"kty": ...}` request, and return the raw JSON body from `sign`. The current `DefaultAzureCredential.init` also returns a value containing pointers into its own movable storage, so credential lifetime must be corrected before it is used by the CA.

## Desired End State

The completed branch will have:

1. A Zig 0.16 package named `sshca`.
2. A reusable library API with allocator-owned public keys, certificate requests, policy validation, and a digest-signer interface.
3. A CLI named `sshca` with these commands:
   - `sshca ca ensure`
   - `sshca ca rotate`
   - `sshca ca public-key`
   - `sshca sign`
4. Azure Key Vault support using `DefaultAzureCredential` and an explicit key version.
5. RSA and Ed25519 subject certificates accepted by OpenSSH.
6. A documented server configuration using `TrustedUserCAKeys`.
7. Unit, interoperability, real-`sshd`, and opt-in live-Azure tests.
8. A Zig-focused README and GitHub Actions workflow.

Verification is complete when:

- `zig build test` passes on macOS and Linux.
- Linux integration tests validate generated certificates with the pinned OpenSSH `ssh-keygen`.
- A containerized `sshd` accepts both an RSA-subject and Ed25519-subject certificate generated by the Zig implementation.
- The opt-in Azure test reuses a pre-provisioned non-exportable RSA CA key version, signs a one-hour certificate through Key Vault, and completes the same SSH login.

## Implementation Progress

- [x] Phase 1: Zig Package and Parity Fixtures
- [x] Phase 2: SSH Wire Format, Public Keys, and PEM
- [x] Phase 3: Certificate Model, Policy, and Signer Boundary
- [x] Phase 4: Complete Azure Key Vault Keys Support in `azure-sdk-for-zig`
- [x] Phase 5: Azure-Backed CA and CLI
- [x] Phase 6: OpenSSH Trust, Login, and Rotation Integration
- [ ] Phase 7: Live Azure Test, CI, Documentation, and Cutover

## Fixed Design Decisions

These decisions remove implementation ambiguity:

- Target exactly Zig 0.16.x; `build.zig.zon` sets `.minimum_zig_version = "0.16.0"`.
- The final `zig16` branch is Zig-first and removes the .NET projects after parity is demonstrated.
- SSH encoding, key parsing, certificate construction, SHA-512 hashing, base64, and JSON-independent core logic are pure Zig.
- OpenSSH is test-only and pinned by commit.
- Azure access uses `azure-sdk-for-zig`, pinned by immutable commit and package hash rather than a moving branch.
- The CA key type is `RSA` by default and `RSA-HSM` when explicitly requested.
- The default CA key size is 3072 bits. Supported values are 2048, 3072, and 4096.
- The Key Vault key operations are only `sign` and `verify`; the private key is non-exportable.
- Key Vault REST API version `2025-07-01` is used unless a newer stable version is deliberately adopted with tests.
- The signing operation is always `RS512`.
- Signing requires an explicit configured active key version. A moving "latest" version is available only through an explicit development flag.
- The low-level library accepts explicit validity timestamps. The high-level issuer defaults to one hour, permits 60 seconds of negative clock skew, and rejects validity periods over eight hours.
- The high-level issuer requires at least one principal.
- The default CLI profile is `interactive`, which grants only `permit-pty`. Agent forwarding, port forwarding, X11 forwarding, and user-rc require explicit flags.
- The signer always uses the exact Key Vault version returned with the CA public key. It never fetches the public key from one version and signs with an unversioned or different key.

## What We Are Not Doing

- Host certificates are not part of the first Zig port; only OpenSSH user certificates are issued.
- Subject-key algorithms other than RSA and Ed25519 are out of scope.
- Ed25519 CA signing is out of scope because the required Azure Key Vault/OpenSSH path is RSA `RS512`.
- The first port does not implement a tenant-specific authorization service that maps Microsoft Entra identities to Unix principals.
- The CLI is not itself a security boundary for untrusted users. Production callers must go through a service that owns the Key Vault signing identity and applies `IssuancePolicy`.
- The OpenSSH C implementation is not linked into the shipped library or CLI.
- Automated distribution of CA trust files to fleets is out of scope; the repository will document the required server state and rotation order.

## Architecture

### Certificate issuance flow

1. Parse the user's `ssh-rsa` or `ssh-ed25519` public-key line.
2. Resolve the configured active Key Vault version and obtain its versioned `kid`, modulus `n`, and exponent `e`.
3. Convert the JWK RSA public material into canonical SSH `ssh-rsa` form.
4. Validate the requested principal set, validity window, extensions, and critical options against `IssuancePolicy`.
5. Serialize the OpenSSH certificate body without its signature.
6. Compute SHA-512 over those exact bytes.
7. Ask Key Vault to sign the 64-byte digest using `RS512` and the same explicit key version.
8. Append the SSH signature blob with algorithm `rsa-sha2-512`.
9. Emit the OpenSSH certificate line and an audit record containing the key version, certificate serial, key ID, principals, validity, and public-key fingerprint.

### Security boundary

The reusable `Issuer` owns policy enforcement. A production service embeds it and is the only identity granted Key Vault signing rights. End users submit a public key and requested target, but the service derives or authorizes principals, clamps validity, and selects extensions before invoking Key Vault.

The administrative CLI is suitable for development, break-glass, and trusted operator workflows. Granting an end user direct Key Vault sign access would let that user bypass certificate policy by submitting arbitrary digests, so that is explicitly not the production model.

## Phase 1: Zig Package and Parity Fixtures

### Overview

Create the Zig 0.16 build, library module, CLI entry point, fixture layout, and test commands while retaining the F# source temporarily as a parity reference.

### Changes Required

#### `build.zig`

- Add the `sshca` module rooted at `src/root.zig`.
- Add the `sshca` executable rooted at `src/main.zig`.
- Add `test`, `integration-test`, and `live-azure-test` build steps.
- Keep OpenSSH and Azure dependencies lazy so core tests do not build them unnecessarily.
- Reserve a separate integration-test target; Phase 3 adds OpenSSL linkage only to the test-only local RSA signer target when that signer exists.

#### `build.zig.zon`

- Set package name, version, fingerprint, paths, and Zig 0.16 minimum.
- Add `openssh_portable` pinned to commit `954c03dd1aef8075ee60ea103e4020213de3e591` for Linux integration tests.
- Defer the `azure_sdk` dependency until Phase 5, after the prerequisite SDK commit exists.

#### `src/root.zig`

- Export the stable library surface without exposing internal wire helpers.

#### `src/main.zig`

- Add the CLI dispatcher and consistent error-to-exit-code mapping.

#### `tests/fixtures/`

- Port the RSA key, Ed25519 key, PEM key, nonce, timestamps, principals, and expected certificate metadata from `SshCATests/TestData.fs`.
- Add PKCS#1 and SubjectPublicKeyInfo PEM fixtures.
- Add OpenSSH-generated fixtures for critical options and extensions.

### Success Criteria

- `zig build` produces the CLI.
- `zig build test` runs a placeholder test without requiring Azure credentials or OpenSSH.
- The package rejects Zig versions older than 0.16.0.

**Implementation note:** Keep the F# projects in place until Phase 7 so expected behavior remains easy to compare.

## Phase 2: SSH Wire Format, Public Keys, and PEM

### Overview

Port the binary primitives and public-key functionality with explicit ownership, canonical mpint handling, and bounded parsing.

### Changes Required

#### `src/wire.zig`

Implement:

- `Reader` over a byte slice with tracked position.
- Big-endian `u32`, `u64`, and signed timestamp-compatible integer reads and writes.
- Length-prefixed SSH string reads and writes.
- Nested buffer construction for principal and option lists.
- Configurable maximum blob length with a 10 MiB absolute ceiling.
- Exact truncation, overflow, invalid-length, and trailing-data errors.

#### `src/public_key.zig`

Implement:

- `PublicKey` tagged union with `.rsa` and `.ed25519`.
- Allocator ownership and `deinit`.
- Parsing of `<algorithm> <base64> [comment]` lines with a 10,000-byte line limit.
- Validation that the outer and embedded algorithms match.
- Exact 32-byte validation for Ed25519 keys.
- Rejection of NUL bytes in comments and other fields later encoded as OpenSSH C strings.
- Canonical unsigned RSA exponent and modulus storage.
- SSH mpint parsing that rejects negative and non-canonical encodings.
- SSH mpint serialization that prepends a zero byte only when required to keep the integer positive.
- Configurable RSA subject-key minimum, defaulting to 2048 bits in the high-level issuer.
- Authorized-key formatting and `cert-authority` formatting.
- Public-key fingerprint generation using SHA-256.

#### `src/pem.zig`

Implement a bounded DER reader supporting:

- PKCS#1 `-----BEGIN RSA PUBLIC KEY-----`.
- SubjectPublicKeyInfo `-----BEGIN PUBLIC KEY-----` with the `rsaEncryption` OID.
- DER `SEQUENCE`, `INTEGER`, `BIT STRING`, `NULL`, and OID forms needed by those structures.
- Rejection of private-key PEM, encrypted PEM, indefinite lengths, negative integers, trailing data, and oversized inputs.

### Success Criteria

- All current valid RSA and Ed25519 public-key fixtures round-trip.
- Algorithm mismatches and malformed or oversized input fail with specific errors.
- RSA keys from Key Vault JWK `n` and `e` format identically to equivalent OpenSSH keys.
- Both supported public PEM forms parse to the same canonical RSA value.

## Phase 3: Certificate Model, Policy, and Signer Boundary

### Overview

Build correct OpenSSH user-certificate bytes and isolate signing behind a digest-based interface suitable for Key Vault.

### Changes Required

#### `src/certificate.zig`

Add:

- `CertificateRequest` with subject key, versioned CA public key, 32-byte nonce, serial, key ID, principals, validity, critical options, extensions, and optional comment.
- Certificate key algorithm selection:
  - RSA subject: `rsa-sha2-512-cert-v01@openssh.com`
  - Ed25519 subject: `ssh-ed25519-cert-v01@openssh.com`
- User certificate type `1`.
- Correct principal-list serialization.
- Empty reserved field.
- Lexical sorting and duplicate rejection for critical options and extensions.
- Typed option values:
  - empty opaque value for permit extensions,
  - nested SSH string for `force-command` and `source-address`,
  - raw bytes for custom extensions.
- Signature blob encoding with `rsa-sha2-512`.
- Shared formatting for synchronous and asynchronous I/O paths so subject algorithm selection cannot diverge.

#### `src/signer.zig`

Define an allocator-aware `DigestSigner` interface whose only cryptographic method signs a `[64]u8` SHA-512 digest and returns an RSA PKCS#1 v1.5 signature.

The certificate layer, not the signer, computes the digest. This prevents different signers from hashing different bytes and maps directly to the Key Vault `RS512` API.

#### `src/policy.zig`

Add `IssuancePolicy` and high-level validation:

- Default TTL: one hour.
- Maximum TTL: eight hours.
- Not-before clock skew: 60 seconds.
- At least one non-empty principal.
- At most 256 principals, matching OpenSSH's certificate limit.
- Non-empty key ID.
- NUL-free key IDs, principals, option names, and text option values.
- RSA subject keys of at least 2048 bits by default.
- Validity represented as unsigned Unix seconds with `valid_before > valid_after`.
- Default interactive profile grants only `permit-pty`.
- Explicit opt-in for forwarding, X11, user-rc, force-command, and source-address.
- Source-address validation for comma-separated IPv4/IPv6 CIDR values.

#### `tests/support/openssl_signer.zig`

- Provide a test-only OpenSSL signer implementing `DigestSigner`.
- Keep all OpenSSL linkage outside the shipped `sshca` module and executable.

### Success Criteria

- Deterministic requests generate stable golden certificate bytes.
- `ssh-keygen -L` reports the expected type, serial, key ID, validity, principals, critical options, and extensions.
- Force-command and source-address fixtures match OpenSSH's nested encoding.
- RSA and Ed25519 subject certificates use the correct outer algorithm.
- Invalid nonce length, validity, duplicate options, or missing principals fail before signing.

## Phase 4: Complete Azure Key Vault Keys Support in `azure-sdk-for-zig`

### Overview

Finish the existing Key Vault keys client instead of duplicating Azure identity and HTTP behavior inside this repository.

**Implemented SDK revision:** `3861c570ef3df55c8c87661a12facf3b6f935190`

**Pinned package hash:** `azure_sdk-0.1.0--PMlNS_bCQBHfCI5K7YidNpHA5R79dNeBf1qj4jRQ5ka`

### Changes Required in `cataggar/azure-sdk-for-zig`

#### `sdk/keyvault/keys/root.zig`

- Replace the preview API default with stable API version `2025-07-01`.
- Wire `BearerTokenAuthPolicy` with scope `https://vault.azure.net/.default`.
- Give `KeyClient` and `CryptographyClient` explicit ownership and `deinit` for authentication policies and policy slices. Do not retain pointers to fields of a client value that may move.
- Add version listing with tags so an ambiguous create response can be reconciled by a per-operation ID.
- Add typed `KeyType`, `KeyOperation`, `SignatureAlgorithm`, and option structures instead of arbitrary strings.
- Add `CreateRsaKeyOptions` with:
  - `RSA` or `RSA-HSM`,
  - key size,
  - `sign` and `verify` operations,
  - enabled state,
  - non-exportable behavior,
  - tags.
- Serialize JSON through the SDK serializer so user-provided tag values cannot break JSON.
- Parse and own:
  - versioned `kid`,
  - key type,
  - key operations,
  - RSA modulus `n`,
  - RSA exponent `e`,
  - exportable state,
  - release policy,
  - tags,
  - enabled and time attributes.
- Decode JWK base64url material into bytes.
- Add an explicit `getKey(name, version)` overload in addition to latest-version lookup.
- Make `sign` accept digest bytes and return decoded signature bytes, not the raw JSON response.
- Validate that `RS512` receives exactly 64 digest bytes.
- Reject an SSH CA key with `exportable=true`, a release policy, or an `export` key operation.
- Preserve structured Azure error codes for 404, 403, throttling, and invalid algorithm responses.
- Mark create and rotate requests as non-retriable. A timeout after sending the request must reconcile by operation tag and version listing rather than blindly resubmit a create that could generate another version.

#### `sdk/core/identity/default_azure_credential.zig`

- Replace self-referential movable storage with caller-owned stable initialization or heap-owned backing credentials.
- Add explicit `deinit`.
- Add a test that obtains a token after the initialized credential has been returned from a helper and moved by the caller.

#### `sdk/core/http/transport.zig` and Key Vault tests

- Extend mock transport inspection to capture request headers and bodies.
- Give request-owned allocated header names and values deterministic cleanup.
- Make `StdHttpTransport` own and reuse a persistent `std.http.Client`, with explicit `deinit` and documented concurrency behavior.
- Assert that Key Vault requests contain an authorization header.
- Assert exact create-key and sign request bodies and base64url behavior.
- Add retry tests for 429 and transient 5xx responses.
- Assert that create and rotate operations bypass automatic retries.

### Success Criteria

- Key clients authenticate with `DefaultAzureCredential`.
- A mocked create response exposes `kid`, version, `n`, and `e`.
- A mocked `RS512` response returns raw signature bytes.
- No Key Vault client silently ignores a credential.
- `DefaultAzureCredential` remains valid after initialization returns.
- The HTTP transport reuses connections without leaking request-owned headers.
- The SDK test suite passes under Zig 0.16.
- The resulting SDK commit is pinned in this repository by immutable commit and package hash.

## Phase 5: Azure-Backed CA and CLI

### Overview

Use the completed SDK to provision a CA key, export its public key, and issue certificates.

### Changes Required

#### `src/azure_key_vault.zig`

Implement:

- `AzureKeyVaultSigner` backed by `CryptographyClient.sign(.RS512, digest)`.
- `ensureCaKey`:
  - GET the latest key.
  - Create only when the key is absent.
  - Reject incompatible existing type, size, operations, or disabled state.
  - Reject exportable keys, release-enabled keys, and keys with an `export` operation.
  - Never create a new version merely because `ensure` was called.
- `rotateCaKey` as the only command that intentionally creates a new version.
- Single-writer provisioning semantics. Concurrent ensure/rotate operations are unsupported without an external distributed lock and are detected where possible through version and operation-tag reconciliation.
- Non-retriable create calls with a unique operation tag. On an ambiguous response, list versions and reconcile before returning an error; never blindly create again.
- Conversion from versioned JWK RSA public material to `PublicKey.rsa`.
- Version extraction from `kid`.
- A result object containing vault URL, key name, version, key ID, and CA public key.
- HTTPS-only vault URL validation against the selected Azure cloud's Key Vault DNS suffix. Reject userinfo, query, fragment, and unrecognized hosts before acquiring a token.

#### `src/issuer.zig`

- Combine policy validation, certificate serialization, SHA-512 hashing, and `DigestSigner`.
- Generate a cryptographically random 32-byte nonce.
- Generate a random non-zero `u64` serial unless one is supplied for deterministic testing.
- Bind the exact versioned CA public key to the exact versioned signer.
- Return the certificate line plus audit metadata.

#### `src/cli.zig`

Implement:

`sshca ca ensure`

- Required: `--vault-url`, `--name`.
- Optional: `--bits 3072`, `--hsm`.
- Output the versioned key ID and SSH CA public key.

`sshca ca rotate`

- Create a new version only after an explicit command.
- Output both old and new CA public-key lines plus rotation instructions.
- Do not change the configured active signing version.

`sshca ca public-key`

- Required: vault URL and key name.
- Optional: explicit version and `--cert-authority`.
- Emit only public information, suitable for redirecting into a trust file.

`sshca sign`

- Required: vault URL, key name, subject public-key file, key ID, and at least one principal.
- Required through an argument, environment variable, or config file: active key version.
- Optional: TTL, output path, profile, extension flags, force-command, source-address, and comment.
- Permit `--latest` only as an explicit development option. When used, first resolve its versioned `kid`, then use that exact version for both public key and sign operations.
- Write atomically to `<identity>-cert.pub` by default.

#### Authentication

- Use `DefaultAzureCredential`.
- Add the repaired `azure_sdk` dependency, pinned to the immutable Phase 4 commit and package hash.
- Select an explicit Azure cloud configuration and derive both the trusted Key Vault hostname suffix and token scope from it.
- Support environment credentials, workload identity, managed identity, and Azure CLI development authentication through the SDK.
- Never accept or log a Key Vault access token on a command line.

### Success Criteria

- `ca ensure` does not create a version when a compatible key already exists.
- `ca rotate` performs one deliberate create request and never blindly retries an ambiguous result.
- `ca public-key` produces a line accepted by `TrustedUserCAKeys`.
- `sign` produces a one-hour certificate by default and rejects a request over eight hours.
- Key Vault receives a 64-byte SHA-512 digest and `RS512`.
- No private CA material appears in process memory, files, logs, or command output.

## Phase 6: OpenSSH Trust, Login, and Rotation Integration

### Overview

Prove that the generated certificate authenticates to a server that trusts the CA, and document the safe operational flow.

**Implemented test image:** `debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef`

**Pinned package source:** Debian snapshot `20250812T000000Z`, OpenSSH `1:9.2p1-2+deb12u6`

### Changes Required

#### `tests/integration/openssh_validation.zig`

- Use the pinned `openssh_portable` `ssh-keygen` artifact on Linux.
- Run `ssh-keygen -L` for RSA and Ed25519 subject certificates.
- Compare parsed metadata rather than temporary file names or generated fingerprints.

#### `tests/integration/sshd-login.sh`

- Start an isolated OpenSSH server from a container image pinned by digest, with the OpenSSH package version pinned through a stable package snapshot.
- Generate ephemeral host and user keys.
- Install the Zig-exported CA public key as the server's `TrustedUserCAKeys`.
- Configure a test account and require public-key authentication.
- Issue a certificate whose principal matches the account.
- Verify a command succeeds using the matching private key and generated certificate.
- Repeat for RSA and Ed25519 subject keys.
- Verify login fails after the certificate's `valid_before`.
- Verify login fails for a non-matching principal.
- Disable ssh-agent use and all default identities, and pass the test private key and certificate explicitly.
- Keep `authorized_keys` empty so a successful login proves CA certificate authentication.

#### `docs/server-trust.md`

Document:

```text
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys
```

Also document:

- File ownership and permissions.
- Reloading `sshd` safely after validating configuration.
- Matching certificate principals to the target Unix account.
- Optional `AuthorizedPrincipalsFile` use.
- Saving the certificate next to the private key as `<identity>-cert.pub`, or using `CertificateFile`.
- The client command pattern `ssh -i <identity> <principal>@<host>`.

#### `docs/key-rotation.md`

Define the required overlap process:

1. Explicitly create a new Key Vault key version.
2. Export the new CA public key.
3. Add both old and new CA public keys to every server.
4. Confirm server trust rollout.
5. Update the configured active issuance version to the new explicit version.
6. Wait at least the maximum certificate TTL plus clock-skew allowance.
7. Remove the old CA public key from servers.
8. Disable the old Key Vault key version only after the trust overlap has completed.

### Success Criteria

- A real `sshd` accepts both supported subject-key types.
- Principal and expiry negative tests fail as expected.
- The documented trust file works without copying a private CA key to any server.
- Rotation instructions prevent certificates from being issued by an untrusted new version.

## Phase 7: Live Azure Test, CI, Documentation, and Cutover

### Overview

Add opt-in Azure validation, make Zig the branch's primary implementation, and remove obsolete .NET artifacts.

### Changes Required

#### `tests/live/keyvault.zig`

- Require explicit environment variables such as `SSHCA_TEST_VAULT_URL`, `SSHCA_TEST_KEY_NAME`, and `SSHCA_TEST_KEY_VERSION`.
- Use `DefaultAzureCredential`.
- Read a pre-provisioned explicit key version, then run public-key export, certificate issuance, OpenSSH inspection, and the containerized SSH login.
- Provision test keys out of band with purpose and repository metadata.
- Never create, update, delete, disable, or rotate a key from the live validation workflow.

#### `.github/workflows/build-and-test.yml`

- Replace the .NET job with Zig 0.16 jobs.
- Run formatting and core tests on Linux and macOS.
- Run pinned OpenSSH and `sshd` integration tests on Linux.
- Install only the existing system dependencies required by the pinned OpenSSH build and test-only OpenSSL signer.

#### `.github/workflows/live-azure.yml`

- Add a manual protected-environment workflow with serialized execution and a fixed test vault/key configuration.
- Authenticate to Azure with GitHub OIDC, not a client secret.
- Use a dedicated test vault per environment.
- Grant the workflow identity only the permissions required for the selected test:
  - provisioning identity: key create/read for out-of-band setup,
  - workflow issuer identity: custom role containing only `Microsoft.KeyVault/vaults/keys/read` and `Microsoft.KeyVault/vaults/keys/sign/action`.
- Do not grant the built-in `Key Vault Crypto User` role to the production issuer because it also includes decrypt, unwrap, backup, and update operations.

**Temporary test-environment exception:** The `vm17kv` live-test identity uses
`Key Vault Crypto User` at the individual vault scope because the tenant has
reached its custom-role definition limit. Replace that assignment with the
read/sign-only custom role as soon as an administrator frees a role slot. The
identity itself is a user-assigned managed identity with GitHub federation, so
its creation does not depend on Microsoft Graph access.

#### `README.md`

- Rewrite usage for Zig library and CLI.
- Include Key Vault setup, CA public-key distribution, certificate issuance, SSH login, managed identity, and rotation examples.
- Explain the distinction between the administrative CLI and a production issuance service.

#### Remove .NET implementation after parity

- Remove `SshCA/`, `SshCATests/`, and `SshCA.sln`.
- Remove NuGet publishing workflow.
- Preserve license attribution and relevant test fixtures.

### Success Criteria

- All normal CI jobs pass without Azure credentials.
- The protected live-Azure workflow completes against a test vault.
- The branch contains only the Zig implementation and its documentation.
- README instructions reproduce an actual SSH login using a time-constrained Key Vault-signed certificate.

## Azure Resource and RBAC Plan

Use a dedicated Key Vault per application and environment, with Azure RBAC, soft delete, purge protection, and TLS 1.2 or later.

Separate identities:

| Identity | Purpose | Permission |
| --- | --- | --- |
| Provisioner | Create and rotate CA key versions | `Key Vault Crypto Officer` during setup, or a narrower custom create/read role |
| Issuer service | Read CA public key and sign SHA-512 digests | Custom role with only `keys/read` and `keys/sign/action` |
| SSH clients | Request certificates | No direct Key Vault access |
| SSH servers | Validate certificates locally | No Azure access; only the CA public key |

Default key request:

```json
{
  "kty": "RSA",
  "key_size": 3072,
  "key_ops": ["sign", "verify"],
  "attributes": {
    "enabled": true,
    "exportable": false
  },
  "tags": {
    "purpose": "openssh-user-ca",
    "managed-by": "sshca-zig"
  }
}
```

Premium-vault deployments may replace `RSA` with `RSA-HSM`.

## Testing Strategy

### Unit Tests

- SSH length-prefix and integer endianness.
- Truncated, oversized, and overflow input.
- Canonical RSA mpint handling.
- RSA and Ed25519 parsing, formatting, comments, and algorithm mismatch.
- PKCS#1 and SubjectPublicKeyInfo PEM parsing.
- Certificate serialization for every field.
- Option sorting, duplicate rejection, and nested option values.
- Validity, principal, nonce, and policy failures.
- Azure JWK conversion.
- Key Vault create/sign JSON and base64url encoding.
- Key-version binding and rotation behavior.

### Integration Tests

- `ssh-keygen -L` metadata validation through the pinned OpenSSH Zig build.
- Local OpenSSL-backed signatures.
- Real containerized `sshd` login.
- RSA and Ed25519 subject keys.
- Expired, future, and wrong-principal rejection.

### Live Azure Tests

- DefaultAzureCredential authentication.
- Idempotent RSA key ensure.
- Versioned public-key retrieval.
- `RS512` signing.
- Real SSH login with the Key Vault signature.
- Explicit rotation and dual-trust overlap.

## Performance Considerations

- Certificate bodies are small; use bounded `ArrayList(u8)` buffers and avoid streaming complexity in the core serializer.
- Hash certificate bytes once and send only the 64-byte digest to Key Vault.
- Reuse the Azure HTTP transport, pipeline, and cached access token for multiple issuances.
- Cache immutable CA public material by versioned `kid`, never by unversioned key name.
- Bound all decoded key, PEM, JSON, and SSH fields before allocation.
- Keep the Key Vault network call as the only required remote operation during steady-state signing after the versioned public key is cached.

## Migration and Rollback

- Keep F# and Zig tests side by side until Zig core parity and OpenSSH interoperability pass.
- Use golden fixtures to detect unintended wire-format changes.
- Do not change server trust during library development.
- Introduce a test CA public key alongside existing trust before the first live login.
- Roll back issuance by returning to the previous pinned Key Vault version; servers continue trusting it during the overlap window.
- Remove the old implementation only after the Zig CI and live-Azure test are both green.

## References

- Existing buffer implementation: `SshCA/SshBuffer.fs`
- Existing public-key implementation: `SshCA/PublicKey.fs`
- Existing certificate implementation: `SshCA/SshCertificate.fs`
- Existing end-to-end tests: `SshCATests/SshCertTests.fs`
- Existing Azure example: `README.md`
- OpenSSH Zig build reference: `https://github.com/cataggar/openssh/tree/zig16-no-automake`
- Azure SDK for Zig Key Vault reference: `https://github.com/cataggar/azure-sdk-for-zig/blob/main/sdk/keyvault/keys/root.zig`
- Azure Key Vault key operations: `https://learn.microsoft.com/azure/key-vault/keys/about-keys-details`
- Azure Key Vault create-key REST API: `https://learn.microsoft.com/rest/api/keyvault/keys/create-key/create-key`
- Azure Key Vault sign REST API: `https://learn.microsoft.com/rest/api/keyvault/keys/sign/sign`
- Azure Key Vault RBAC guidance: `https://learn.microsoft.com/azure/key-vault/general/rbac-guide`
