const std = @import("std");
const sshca = @import("sshca");

const c = @cImport({
    @cInclude("openssl/bn.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
});

pub const OpenSslSigner = struct {
    key: *c.EVP_PKEY,

    pub fn init(bits: c_int) !OpenSslSigner {
        const context = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse
            return error.OpenSslKeyContext;
        defer c.EVP_PKEY_CTX_free(context);
        if (c.EVP_PKEY_keygen_init(context) <= 0) return error.OpenSslKeyGeneration;
        if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(context, bits) <= 0) {
            return error.OpenSslKeyGeneration;
        }

        var key: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_keygen(context, &key) <= 0 or key == null) {
            return error.OpenSslKeyGeneration;
        }
        return .{ .key = key.? };
    }

    pub fn deinit(self: *OpenSslSigner) void {
        c.EVP_PKEY_free(self.key);
    }

    pub fn digestSigner(self: *OpenSslSigner) sshca.DigestSigner {
        return sshca.DigestSigner.init(self, sign);
    }

    pub fn publicKey(
        self: OpenSslSigner,
        allocator: std.mem.Allocator,
    ) !sshca.PublicKey {
        const exponent = try self.parameterBytes(
            allocator,
            c.OSSL_PKEY_PARAM_RSA_E,
        );
        defer allocator.free(exponent);
        const modulus = try self.parameterBytes(
            allocator,
            c.OSSL_PKEY_PARAM_RSA_N,
        );
        defer allocator.free(modulus);
        return sshca.PublicKey.initRsa(allocator, exponent, modulus, null);
    }

    pub fn verifyDigest(
        self: OpenSslSigner,
        digest: *const [64]u8,
        signature: []const u8,
    ) !void {
        const verification_context = c.EVP_PKEY_CTX_new(self.key, null) orelse
            return error.OpenSslVerificationContext;
        defer c.EVP_PKEY_CTX_free(verification_context);
        if (c.EVP_PKEY_verify_init(verification_context) <= 0) {
            return error.OpenSslVerification;
        }
        if (c.EVP_PKEY_CTX_set_rsa_padding(
            verification_context,
            c.RSA_PKCS1_PADDING,
        ) <= 0) return error.OpenSslVerification;
        if (c.EVP_PKEY_CTX_set_signature_md(
            verification_context,
            c.EVP_sha512(),
        ) <= 0) return error.OpenSslVerification;
        if (c.EVP_PKEY_verify(
            verification_context,
            signature.ptr,
            signature.len,
            digest,
            digest.len,
        ) != 1) return error.OpenSslVerification;
    }

    fn parameterBytes(
        self: OpenSslSigner,
        allocator: std.mem.Allocator,
        name: [*c]const u8,
    ) ![]u8 {
        var number: ?*c.BIGNUM = null;
        if (c.EVP_PKEY_get_bn_param(self.key, name, &number) != 1 or number == null) {
            return error.OpenSslKeyParameter;
        }
        defer c.BN_free(number);

        const bit_count = c.BN_num_bits(number);
        if (bit_count <= 0) return error.OpenSslKeyParameter;
        const byte_count: usize = @intCast(@divTrunc(bit_count + 7, 8));
        const bytes = try allocator.alloc(u8, byte_count);
        errdefer allocator.free(bytes);
        if (c.BN_bn2bin(number, bytes.ptr) != byte_count) {
            return error.OpenSslKeyParameter;
        }
        return bytes;
    }

    fn sign(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        digest: *const [64]u8,
    ) ![]u8 {
        const self: *OpenSslSigner = @ptrCast(@alignCast(context));
        const signing_context = c.EVP_PKEY_CTX_new(self.key, null) orelse
            return error.OpenSslSigningContext;
        defer c.EVP_PKEY_CTX_free(signing_context);
        if (c.EVP_PKEY_sign_init(signing_context) <= 0) return error.OpenSslSigning;
        if (c.EVP_PKEY_CTX_set_rsa_padding(
            signing_context,
            c.RSA_PKCS1_PADDING,
        ) <= 0) return error.OpenSslSigning;
        if (c.EVP_PKEY_CTX_set_signature_md(
            signing_context,
            c.EVP_sha512(),
        ) <= 0) return error.OpenSslSigning;

        var signature_len: usize = 0;
        if (c.EVP_PKEY_sign(
            signing_context,
            null,
            &signature_len,
            digest,
            digest.len,
        ) <= 0) return error.OpenSslSigning;
        const signature = try allocator.alloc(u8, signature_len);
        errdefer allocator.free(signature);
        if (c.EVP_PKEY_sign(
            signing_context,
            signature.ptr,
            &signature_len,
            digest,
            digest.len,
        ) <= 0) return error.OpenSslSigning;
        return allocator.realloc(signature, signature_len);
    }
};
