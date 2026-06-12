SshCA
=====

[![Build and Test](https://github.com/ninjarobot/SshCa/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/ninjarobot/SshCa/actions/workflows/build-and-test.yml)
[![SshCa on Nuget](https://img.shields.io/nuget/v/SshCA)](https://www.nuget.org/packages/SshCA/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ninjarobot/SshCa)

Use SSH public key and and CA certificates to sign SSH public keys. It can be used to read and write SSH public keys, convert between dotnet RSA public keys and the OpenSSH format, and to sign OpenSSH public keys in the format used by OpenSSH.

See the [SshCATests](SshCATests) project for examples.

### Features
* Parse OpenSSH public keys in `ssh-rsa` (RSA) or `ssh-ed25519` (Edwards Curve 25519) format.
* Sign OpenSSH public keys with an RSA implementation such as `System.Security.Cryptography.RSA` or the one returned by `Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient.CreateRSA`.
* Convert `ssh-rsa` OpenSSH keys to RSA public keys.
* Read RSA public keys from a PEM file for use with signing.
* Write RSA public keys as OpenSSH public keys.
* Safe parsing with `TryParse*` methods that don't throw exceptions
* Helper methods for adding common certificate extensions and critical options

### Important Information

* Conversion between RSA and OpenSSH public keys always formats them as `ssh-rsa`.
* Certificates need to be signed with SHA-512 as the signatures are always formatted as `rsa-sha2-512`.
* The `ssh-rsa` and `ssh-ed25519` algorithms are currently supported. Parsing validates that the algorithm matches between the key line and embedded data.
* When signing `ssh-rsa` public keys, the generated certificate algorithm is always `rsa-sha2-512-cert-v01@openssh.com`.
* When signing `ssh-ed25519` public keys, the generated certificate algorithm is always `ssh-ed25519-cert-v01@openssh.com`.
* Regardless of the type of public key being signed, they are always signed with an RSA CA key pair at this time.

The goal is to allow external service to sign SSH keys, so this gives some flexibility in what RSA implementation is
used for signing (dotnet RSA, OpenSSL, external call to Azure Key Vault or AWS KMS, maybe you have an HSM). Whichever
implementation is used, it should be signed with an RSA private key using SHA-512.

### Usage

This example uses an RSA key in Azure Key Vault to sign an SSH public key.
```csharp
using SshCA;
using System.IO;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;

// Read your existing SSH public key
var mySshPubKey =
    File.ReadAllText(
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".ssh",
            "id_rsa.pub"
        )
    );
var pubKey = PublicKey.ParseSshPublicKey(mySshPubKey);

// Get the CA public key from Azure Key Vault
var cred = new Azure.Identity.DefaultAzureCredential();
var keyClient = new KeyClient(new Uri("https://mykeyvault.vault.azure.net"), cred);
var caRsaPubKey = keyClient.GetKey("ssh-signing-key");

// Convert the CA public key to OpenSSH format.
SshCA.PublicKey caPubKey = null;
string caPubKeySsh = null;
using (var rsa = caRsaPubKey.Value.Key.ToRSA()) {
    var caPubKeyPem = rsa.ExportRSAPublicKeyPem();
    caPubKey = SshCA.PublicKey.ParseRsaPublicKeyPem(caPubKeyPem);
    caPubKeySsh = SshCA.PublicKey.ToSshPublicKey(caPubKey);
}
// Note: the OpenSSH formatted key `caPubKeySsh` should be added to a file and
// that file's path set in the TrustedUserCAKeys in your sshd_config. Or you can
// generate a cert-authority line to add to an individual authorized_keys file.

var certAuthLine = PublicKey.ToSshCertAuthority(caPubKey);

// Create certificate information. The key_id is going to show in the SSH logs when you use this certificate.
var certInfo = new CertificateInfo("my-account@linux-server", pubKey, caPubKey);
certInfo.ValidAfter = DateTimeOffset.Now;
certInfo.ValidBefore = certInfo.ValidAfter.AddHours(1); // This signature is only good for an hour.
certInfo.Principals = new List<string>() {"linuxuser"}; // Whatever user(s) you can login as.

// Add extensions using helper methods
certInfo.AddPermitPty();              // Required for interactive shells
certInfo.AddPermitAgentForwarding();  // Allow ssh-agent forwarding
certInfo.AddPermitPortForwarding();   // Allow port forwarding
// Or use AddAllPermitExtensions() to add all common extensions at once

// Sign it using the CA private key. This signing happens in the Key Vault itself.
var cryptoClient = new CryptographyClient(new Uri("https://mykeyvault.vault.azure.net/keys/ssh-signing-key"), cred);

String signedCert = null;
using(var rsa = cryptoClient.CreateRSA()) {
    // Certificates must be signed with SHA-512.
    var certAuth = new CertificateAuthority(ms => rsa.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
    var signedCert = certAuth.SignAndSerialize(certInfo, "comment-such-as:my-account@linux-server");    
}

// Write it out and it's ready to use.
File.WriteAllText(
    Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".ssh",
        "id_rsa-cert.pub"
    ),
    signedCert
);
```

### Safe Parsing with TryParse Methods

For scenarios where you want to handle parse failures gracefully without exceptions, use the `TryParse*` methods:

```csharp
using SshCA;

// Safe parsing of SSH public key
PublicKey pubKey;
if (PublicKey.TryParseSshPublicKey(sshKeyString, out pubKey))
{
    // Successfully parsed
    Console.WriteLine($"Algorithm: {pubKey.Algorithm}");
}
else
{
    // Parsing failed - invalid format, null input, etc.
    Console.WriteLine("Failed to parse SSH public key");
}

// Safe parsing of PEM format
PublicKey pemPubKey;
if (PublicKey.TryParseRsaPublicKeyPem(pemString, out pemPubKey))
{
    // Successfully parsed
    var sshKey = PublicKey.ToSshPublicKey(pemPubKey);
}

// Safe parsing with a comment
PublicKey pemPubKeyWithComment;
if (PublicKey.TryParseRsaPublicKeyPem(pemString, "my-key-comment", out pemPubKeyWithComment))
{
    Console.WriteLine($"Comment: {pemPubKeyWithComment.Comment}");
}
```

The `TryParse*` methods return `false` and set the out parameter to `null` for any of these conditions:
- Null or empty input
- Invalid base64 encoding
- Malformed key data
- Oversized input (>10,000 characters for SSH keys)
- Invalid PEM format

### Adding Extensions and Critical Options

The `CertificateInfo` class provides helper methods to easily add common extensions and critical options:

```csharp
using SshCA;

var certInfo = new CertificateInfo("user@host", publicKey, caPublicKey);

// Add individual extensions
certInfo.AddPermitPty();              // Allow pseudo-terminal allocation (required for shells)
certInfo.AddPermitAgentForwarding();  // Allow ssh-agent forwarding
certInfo.AddPermitPortForwarding();   // Allow port forwarding
certInfo.AddPermitX11Forwarding();    // Allow X11 forwarding
certInfo.AddPermitUserRc();           // Allow execution of ~/.ssh/rc

// Or add all common extensions at once
certInfo.AddAllPermitExtensions();

// Add custom extensions
certInfo.AddExtension("my-custom-extension", "optional-data");

// Add critical options
certInfo.AddForceCommand("/usr/bin/restricted-shell");  // Force a specific command
certInfo.AddSourceAddress("192.168.1.0/24,10.0.0.0/8"); // Restrict source addresses

// Add custom critical options
certInfo.AddCriticalOption("my-option", "value");
```

**Available Extension Helpers:**
- `AddPermitPty()` - Required for interactive shells
- `AddPermitAgentForwarding()` - Allow SSH agent forwarding
- `AddPermitPortForwarding()` - Allow port forwarding  
- `AddPermitX11Forwarding()` - Allow X11 forwarding
- `AddPermitUserRc()` - Allow execution of ~/.ssh/rc
- `AddAllPermitExtensions()` - Adds all of the above

**Available Critical Option Helpers:**
- `AddForceCommand(command)` - Force execution of a specific command
- `AddSourceAddress(cidrList)` - Restrict valid source addresses (comma-separated CIDR blocks)