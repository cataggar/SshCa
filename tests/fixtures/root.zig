pub const rsa_authorized_key = @embedFile("rsa.pub");
pub const rsa_authorized_key_long_comment = @embedFile("rsa-long-comment.pub");
pub const ed25519_authorized_key = @embedFile("ed25519.pub");
pub const rsa_public_key_pkcs1_pem = @embedFile("rsa-public-pkcs1.pem");
pub const rsa_public_key_spki_pem = @embedFile("rsa-public-spki.pem");
pub const certificate_metadata = @embedFile("certificate-metadata.txt");
pub const openssh_options_certificate = @embedFile("openssh-options-cert.pub");
pub const openssh_options_metadata = @embedFile("openssh-options-metadata.txt");

pub const nonce = [_]u8{0} ** 32;
pub const serial: u64 = 0;
pub const valid_after: u64 = 1_749_801_600;
pub const valid_before: u64 = 1_749_808_800;
pub const key_id = "testkey";
pub const principals = [_][]const u8{"someUser"};
pub const force_command = "/usr/bin/restricted-shell";
pub const source_address = "192.0.2.0/24,2001:db8::/32";
pub const permit_extensions = [_][]const u8{
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
    "permit-X11-forwarding",
};
