(*
The MIT License (MIT)
Copyright © 2025-2026 Dave Curylo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*)
namespace SshCA

open System
open System.IO
open System.Security.Cryptography
open System.Collections.Generic

/// Common SSH certificate extensions that can be included in user certificates.
module CertificateExtensions =
    /// Allows allocation of a pseudo-terminal (pty). Required for interactive shells.
    [<Literal>]
    let PermitPty = "permit-pty"
    
    /// Allows forwarding of the ssh-agent.
    [<Literal>]
    let PermitAgentForwarding = "permit-agent-forwarding"
    
    /// Allows port forwarding.
    [<Literal>]
    let PermitPortForwarding = "permit-port-forwarding"
    
    /// Allows X11 forwarding.
    [<Literal>]
    let PermitX11Forwarding = "permit-X11-forwarding"
    
    /// Allows execution of ~/.ssh/rc.
    [<Literal>]
    let PermitUserRc = "permit-user-rc"

/// Common SSH certificate critical options.
module CertificateCriticalOptions =
    /// Forces a specific command to be executed. The command string should be provided as the value.
    [<Literal>]
    let ForceCommand = "force-command"
    
    /// Restricts the source addresses from which the certificate is valid.
    /// The value should be a comma-separated list of CIDR blocks.
    [<Literal>]
    let SourceAddress = "source-address"

/// <summary>
/// Contains information about a certificate to be signed.
/// Note: This class is not thread-safe and should not be shared across threads.
/// </summary>
type CertificateInfo(keyId:string, publicKeyToSign:PublicKey, caPublicKey:PublicKey, nonce:byte array) =
    let mutable extensions = ResizeArray<string * string>()
    let mutable criticalOptions = ResizeArray<string * string>()
    
    member val Nonce = nonce with get, set
    member val PublicKeyToSign = publicKeyToSign with get
    member val Serial = 0UL with get, set
    member val KeyId = keyId with get, set
    member val Principals = Array.Empty<string>() :> System.Collections.Generic.IEnumerable<string> with get, set
    member val ValidAfter = DateTimeOffset.MinValue with get, set
    member val ValidBefore = DateTimeOffset.MinValue with get, set
    
    /// Gets the critical options as a sequence of strings (legacy format).
    /// The sequence contains alternating name and value strings.
    /// Note: The getter creates a new sequence on each access. Cache the result if accessing repeatedly.
    /// To add critical options, use the AddCriticalOption or AddForceCommand/AddSourceAddress helper methods.
    member _.CriticalOptions 
        with get() = 
            let result = ResizeArray<string>(criticalOptions.Count * 2)
            for (name, value) in criticalOptions do
                result.Add(name)
                result.Add(value)
            result :> IEnumerable<string>
        /// Sets the critical options using alternating name-value pairs.
        /// <remarks>This setter is deprecated. Use AddCriticalOption, AddForceCommand, or AddSourceAddress instead for a clearer API.</remarks>
        and [<System.Obsolete("Setting CriticalOptions with the property setter is deprecated. Use AddCriticalOption(name, value) or AddForceCommand/AddSourceAddress helper methods instead for better clarity.", false)>] set(value) = 
            criticalOptions.Clear()
            if not (obj.ReferenceEquals(value, null)) then
                // Convert IEnumerable to array using BCL List<T>
                let valueSeq = value :> IEnumerable<string>
                let items = List<string>(valueSeq).ToArray()
                for i in 0 .. 2 .. items.Length - 1 do
                    if i + 1 < items.Length then
                        criticalOptions.Add((items[i], items[i + 1]))
    
    /// Gets the extensions as a sequence of strings (legacy format).
    /// The sequence contains alternating name and value strings.
    /// Note: The getter creates a new sequence on each access. Cache the result if accessing repeatedly.
    /// To add extensions, use the AddExtension or AddPermit* helper methods.
    member _.Extensions 
        with get() = 
            let result = ResizeArray<string>(extensions.Count * 2)
            for (name, value) in extensions do
                result.Add(name)
                result.Add(value)
            result :> IEnumerable<string>
        /// Sets the extensions using alternating name-value pairs.
        /// <remarks>This setter is deprecated. Use AddExtension, AddPermitPty, or other helper methods instead for a clearer API.</remarks>
        and [<System.Obsolete("Setting Extensions with the property setter is deprecated. Use AddExtension(name, value) or AddPermit* helper methods instead for better clarity.", false)>] set(value) = 
            extensions.Clear()
            if not (obj.ReferenceEquals(value, null)) then
                // Convert IEnumerable to array using BCL List<T>
                let valueSeq = value :> IEnumerable<string>
                let items = List<string>(valueSeq).ToArray()
                for i in 0 .. 2 .. items.Length - 1 do
                    if i + 1 < items.Length then
                        extensions.Add((items[i], items[i + 1]))
    
    member val CaPublicKey = caPublicKey with get
    
    /// Adds an extension to the certificate.
    /// Common extensions: permit-pty, permit-agent-forwarding, permit-port-forwarding, permit-X11-forwarding, permit-user-rc
    /// Most extensions have empty data (pass empty string).
    member _.AddExtension(name: string, data: string) =
        if String.IsNullOrEmpty(name) then invalidArg "name" "Extension name cannot be null or empty"
        let dataValue = if isNull data then "" else data
        extensions.Add((name, dataValue))
        
    /// Adds an extension with no data to the certificate.
    /// Common extensions: permit-pty, permit-agent-forwarding, permit-port-forwarding, permit-X11-forwarding, permit-user-rc
    member this.AddExtension(name: string) =
        this.AddExtension(name, "")
    
    /// Adds the permit-pty extension, which allows allocation of a pseudo-terminal.
    /// This is required for interactive shells.
    member this.AddPermitPty() =
        this.AddExtension(CertificateExtensions.PermitPty)
    
    /// Adds the permit-agent-forwarding extension, which allows forwarding of the ssh-agent.
    member this.AddPermitAgentForwarding() =
        this.AddExtension(CertificateExtensions.PermitAgentForwarding)
    
    /// Adds the permit-port-forwarding extension, which allows port forwarding.
    member this.AddPermitPortForwarding() =
        this.AddExtension(CertificateExtensions.PermitPortForwarding)
    
    /// Adds the permit-X11-forwarding extension, which allows X11 forwarding.
    member this.AddPermitX11Forwarding() =
        this.AddExtension(CertificateExtensions.PermitX11Forwarding)
    
    /// Adds the permit-user-rc extension, which allows execution of ~/.ssh/rc.
    member this.AddPermitUserRc() =
        this.AddExtension(CertificateExtensions.PermitUserRc)
    
    /// Adds all common permit extensions (pty, agent-forwarding, port-forwarding, X11-forwarding, user-rc).
    member this.AddAllPermitExtensions() =
        this.AddPermitPty()
        this.AddPermitAgentForwarding()
        this.AddPermitPortForwarding()
        this.AddPermitX11Forwarding()
        this.AddPermitUserRc()
    
    /// Adds a critical option to the certificate.
    /// Common critical options: force-command (with command string), source-address (with CIDR list)
    member _.AddCriticalOption(name: string, data: string) =
        if String.IsNullOrEmpty(name) then invalidArg "name" "Critical option name cannot be null or empty"
        let dataValue = if isNull data then "" else data
        criticalOptions.Add((name, dataValue))
    
    /// Adds the force-command critical option, which forces execution of a specific command.
    member this.AddForceCommand(command: string) =
        if String.IsNullOrEmpty(command) then invalidArg "command" "Command cannot be null or empty"
        this.AddCriticalOption(CertificateCriticalOptions.ForceCommand, command)
    
    /// Adds the source-address critical option, which restricts source addresses.
    /// Accepts a comma-separated list of CIDR blocks (e.g., "192.168.1.0/24,10.0.0.0/8").
    member this.AddSourceAddress(cidrList: string) =
        if String.IsNullOrEmpty(cidrList) then invalidArg "cidrList" "CIDR list cannot be null or empty"
        this.AddCriticalOption(CertificateCriticalOptions.SourceAddress, cidrList)

    new (keyId:string, publicKeyToSign:PublicKey, caPublicKey:PublicKey) =
        CertificateInfo(keyId, publicKeyToSign, caPublicKey, RandomNumberGenerator.GetBytes 32)

module private CertificateSigning =
    /// User certificate is 1u: https://github.com/openssh/openssh-portable/blob/edc601707b583a2c900e49621e048c26574edd3a/ssh2.h#L179
    let SSH2_CERT_TYPE_USER = 1u
    
    /// Certificate signing algorithm is SHA-512 and signing an RSA public key.
    let RSA_SHA_512_CERT_ALG = "rsa-sha2-512-cert-v01@openssh.com"
    /// Certificate is signing an ED25519 public key. 
    let ED25519_CERT_ALG = "ssh-ed25519-cert-v01@openssh.com"

    /// Writes a sequence of strings to a new buffer and returns the data.
    let stringsToBuffer (s:string seq) =
        use ms = new MemoryStream()
        let sshBuf = SshBuffer(ms)
        if not (obj.ReferenceEquals(s, null)) then
            for item in s do
                sshBuf.WriteSshString item
        ms.ToArray()

    /// Builds the certificate contents ready to sign in a MemoryStream.
    let buildCertificateContentStream (certInfo:CertificateInfo) =
        let keyType = SSH2_CERT_TYPE_USER
        
        let reserved = 0u |> BitConverter.GetBytes // Empty string for now (this is a size of 0).
        
        // Super helpful presentation explaining these fields:
        // https://www.ietf.org/proceedings/122/slides/slides-122-sshm-openssh-certificate-format-00.pdf
        let certMs = new MemoryStream()
        let certSshBuf = SshBuffer(certMs)
        if certInfo.PublicKeyToSign.Algorithm = RsaPublicKey.SshRsa then
            RSA_SHA_512_CERT_ALG |> certSshBuf.WriteSshString
        elif certInfo.PublicKeyToSign.Algorithm = Ed25519PublicKey.SshEd25519 then
            ED25519_CERT_ALG |> certSshBuf.WriteSshString
        else
            invalidOp $"Unsupported public key algorithm {certInfo.PublicKeyToSign.Algorithm}"
        certInfo.Nonce |> certSshBuf.WriteSshData
        certInfo.PublicKeyToSign.WritePublicKeyComponents certSshBuf
        certInfo.Serial |> certSshBuf.WriteSshData
        keyType |> certSshBuf.WriteSshData
        certInfo.KeyId |> certSshBuf.WriteSshString
        certInfo.Principals |> stringsToBuffer |> certSshBuf.WriteSshData
        certInfo.ValidAfter.ToUnixTimeSeconds() |> certSshBuf.WriteSshData
        certInfo.ValidBefore.ToUnixTimeSeconds() |> certSshBuf.WriteSshData
        certInfo.CriticalOptions |> stringsToBuffer |> certSshBuf.WriteSshData
        certInfo.Extensions |> stringsToBuffer |> certSshBuf.WriteSshData
        reserved |> certSshBuf.WriteSshData
        certInfo.CaPublicKey.AsSshPublicKeyBytes |> certSshBuf.WriteSshData
        certMs

    /// Signs the certificate content and returns that signature. The memory stream containing
    /// the certificate content will be at the same position after signing.
    let sign (signData:Stream -> byte array) (certContents:MemoryStream) =
        use dataToSign = new MemoryStream()
        certContents.Position <- 0L
        certContents.CopyTo(dataToSign)
        // Have to set the position to the beginning before signing or it will produce and invalid signature.
        dataToSign.Position <- 0
        dataToSign |> signData

    let signAsync (signData:Func<Stream, System.Threading.CancellationToken, System.Threading.Tasks.Task<byte array>>) (cancellationToken:System.Threading.CancellationToken) (certContents:MemoryStream) =
        backgroundTask {
            use dataToSign = new MemoryStream()
            certContents.Position <- 0L
            certContents.CopyTo(dataToSign)
            // Have to set the position to the beginning before signing or it will produce and invalid signature.
            dataToSign.Position <- 0
            return! signData.Invoke(dataToSign, cancellationToken)
        }

    /// Appends the signature to the certificate content stream.
    let appendSignature (certContents:Stream) (signature:byte array) =
        use ms = new MemoryStream()
        let sshBuf = SshBuffer(ms)
        "rsa-sha2-512" |> sshBuf.WriteSshString
        signature |> sshBuf.WriteSshData
        // Append the whole thing as a string for the signature blob
        ms.ToArray() |> SshBuffer(certContents).WriteSshData

    /// Writes the certificate contents to a byte array.
    let getCertificateBytes(certContents:MemoryStream) =
        certContents.ToArray()

[<Sealed>]
type CertificateAuthority(signData:Func<Stream, byte array>) =

    /// Builds and signs and SSH certificate, returning the certificate contents.
    member _.Sign(certInfo:CertificateInfo) =
        if obj.ReferenceEquals(certInfo, null) then
            nullArg "certInfo"
        if certInfo.Nonce.Length <> 32 then
            invalidArg "certInfo.Nonce" "Nonce must be 32 bytes."
        use ms = CertificateSigning.buildCertificateContentStream(certInfo)
        ms
        |> CertificateSigning.sign signData.Invoke
        |> CertificateSigning.appendSignature ms
        CertificateSigning.getCertificateBytes ms

    /// Builds and signs an SSH certificate, returning the contents in OpenSSH serialized format.
    member this.SignAndSerialize (certInfo:CertificateInfo, comment:string) =
        if obj.ReferenceEquals(certInfo, null) then
            nullArg "certInfo"
        let certBytes = certInfo |> this.Sign
        let b64Cert = certBytes |> Convert.ToBase64String
        let alg =
            if certInfo.PublicKeyToSign.Algorithm = RsaPublicKey.SshRsa then
                CertificateSigning.RSA_SHA_512_CERT_ALG
            elif certInfo.PublicKeyToSign.Algorithm = Ed25519PublicKey.SshEd25519 then
                CertificateSigning.ED25519_CERT_ALG
            else
                invalidOp $"Unsupported public key algorithm {certInfo.PublicKeyToSign.Algorithm}"
        if String.IsNullOrWhiteSpace comment then
            String.Format("{0} {1}", alg, b64Cert)
        else
            String.Format("{0} {1} {2}", alg, b64Cert, comment)

[<Sealed>]
type CertificateAuthorityAsync(signDataAsync:Func<Stream, System.Threading.CancellationToken, System.Threading.Tasks.Task<byte array>>) =
    member _.SignAsync(certInfo:CertificateInfo, cancellationToken:System.Threading.CancellationToken) =
        if obj.ReferenceEquals(certInfo, null) then
            nullArg "certInfo"
        if certInfo.Nonce.Length <> 32 then
            invalidArg "certInfo.Nonce" "Nonce must be 32 bytes."
        backgroundTask {
            use ms = CertificateSigning.buildCertificateContentStream(certInfo)
            let! signature =
                ms
                |> CertificateSigning.signAsync signDataAsync cancellationToken
            signature |> CertificateSigning.appendSignature ms
            return CertificateSigning.getCertificateBytes ms
        }

    member this.SignAsync(certInfo:CertificateInfo) =
        this.SignAsync(certInfo, System.Threading.CancellationToken.None)

    member this.SignAndSerializeAsync (certInfo:CertificateInfo, comment:string) =
        backgroundTask {
            if obj.ReferenceEquals(certInfo, null) then
                nullArg "certInfo"
            let! certBytes = certInfo |> this.SignAsync
            let b64Cert = certBytes |> Convert.ToBase64String
            return
                if String.IsNullOrWhiteSpace comment then
                    String.Format("{0} {1}", CertificateSigning.RSA_SHA_512_CERT_ALG, b64Cert)
                else
                    String.Format("{0} {1} {2}", CertificateSigning.RSA_SHA_512_CERT_ALG, b64Cert, comment)
        }
