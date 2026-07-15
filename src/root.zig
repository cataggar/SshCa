//! OpenSSH certificate authority primitives for Zig 0.16.

const std = @import("std");
const wire = @import("wire.zig");

pub const version = "0.1.0";

pub const public_key = @import("public_key.zig");
pub const pem = @import("pem.zig");
pub const signer = @import("signer.zig");
pub const certificate = @import("certificate.zig");
pub const policy = @import("policy.zig");
pub const azure_key_vault = @import("azure_key_vault.zig");
pub const azure_credential = @import("azure_credential.zig");
pub const issuer = @import("issuer.zig");
pub const cli = @import("cli.zig");

pub const SubjectAlgorithm = public_key.Algorithm;
pub const PublicKey = public_key.PublicKey;
pub const parseAuthorizedKey = public_key.parseAuthorizedKey;
pub const parseRsaPublicKeyPem = pem.parseRsaPublicKey;
pub const DigestSigner = signer.DigestSigner;
pub const CertificateRequest = certificate.CertificateRequest;
pub const IssuancePolicy = policy.IssuancePolicy;

test "package exports public key primitives" {
    try std.testing.expect(version.len > 0);
    try std.testing.expectEqual(SubjectAlgorithm.rsa, SubjectAlgorithm.rsa);
    std.testing.refAllDecls(@This());
    _ = wire;
}
