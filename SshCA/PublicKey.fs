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
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text

[<AbstractClass; AllowNullLiteral>]
type PublicKey(algorithm:string, comment:string) =
    /// Represents a public key used in cryptographic algorithms.
    ///
    /// The `PublicKey` type includes properties and methods necessary for creating, managing,
    /// and converting public keys for SSH and other use cases. It includes fields such as
    /// `Algorithm`, `Exponent`, `Modulus`, and an optional `Comment`.
    member val Algorithm: string = algorithm with get

    /// Represents a public key with associated metadata and functionality.
    ///
    /// A PublicKey contains properties such as the algorithm, key bytes, and an optional comment.
    /// It also provides methods to perform operations like converting the PublicKey instance into a format
    /// compatible with SSH public key representations.
    member val Comment: string = comment with get
    
    /// Writes components of the public key to an SshBuffer for serialization.
    abstract member WritePublicKeyComponents: SshBuffer -> unit
    
    /// Converts a `PublicKey` instance into a byte array formatted according to the SSH public key standard.
    ///
    /// The function writes the `Algorithm` string, `Exponent`, and `Modulus` of the `PublicKey` instance
    /// into a `MemoryStream` in the required SSH buffer format, and then retrieves the resulting byte array.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the algorithm, exponent, and modulus fields to be formatted.
    ///
    /// Returns:
    ///   A byte array representing the SSH public key in the required format.
    member this.AsSshPublicKeyBytes =
        use ms = new MemoryStream()
        let sshBuf = SshBuffer(ms)
        this.Algorithm |> (Encoding.UTF8.GetBytes >> sshBuf.WriteSshData)
        this.WritePublicKeyComponents sshBuf
        ms.ToArray()

    member this.AsSshPublicKey =
        let pkBytes = this.AsSshPublicKeyBytes
        if String.IsNullOrWhiteSpace this.Comment then
            String.Format(
                "{0} {1}",
                this.Algorithm,
                Convert.ToBase64String pkBytes
            )
        else
            String.Format(
                "{0} {1} {2}",
                this.Algorithm,
                Convert.ToBase64String pkBytes,
                this.Comment
            )

    override this.ToString() =
        this.AsSshPublicKey

/// Represents a public key adhering to the SSH public key standard.
///
/// This type encapsulates properties and methods for handling and formatting
/// public key information, including the algorithm, public key components, and an
/// optional comment. It provides functionality for parsing keys from strings
/// and converting keys to their SSH public key representation.
type RsaPublicKey(exponent:byte array, modulus:byte array, comment:string) =
    inherit PublicKey(RsaPublicKey.SshRsa, comment)
    /// Represents the identifier for the RSA algorithm in the context
    /// of SSH public key operations. The value is a literal string
    /// "ssh-rsa", which is used to specify the RSA algorithm type in
    /// SSH key exchanges and related operations.
    static member SshRsa = "ssh-rsa"

    /// Represents the exponent value of a public RSA key as a byte array.
    ///
    /// The exponent is a critical component of the RSA public key used
    /// in cryptographic algorithms. This property provides read-only
    /// access to the exponent value stored in the `PublicKey` instance.
    member val Exponent: byte array = exponent with get

    /// The `Modulus` property represents the modulus component of a public key, stored as a byte array.
    /// This is a read-only property that returns the modulus, a critical part of the cryptographic
    /// public key used in various operations, including SSH key generation and RSA encryption.
    member val Modulus: byte array = modulus with get

    /// Represents an SSH public key with RSA algorithm and associated parameters.
    ///
    /// Properties:
    /// - Algorithm: Represents the type of the algorithm (e.g., "ssh-rsa").
    /// - Exponent: The public exponent of the RSA key.
    /// - Modulus: The modulus of the RSA key.
    /// - Comment: An optional comment associated with the public key.
    new(exponent, modulus) = RsaPublicKey(exponent, modulus, null)

    override this.WritePublicKeyComponents (sshBuf:SshBuffer) =
        this.Exponent |> sshBuf.WriteSshData
        this.Modulus |> sshBuf.WriteSshData

    interface IEquatable<RsaPublicKey> with
        member this.Equals (other: RsaPublicKey) =
            this.Algorithm = other.Algorithm &&
            System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(this.Exponent, other.Exponent) &&
            System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(this.Modulus, other.Modulus) &&
            this.Comment = other.Comment

    override this.Equals(other) =
        if Object.ReferenceEquals(this,other) then true
        else
            match other with
            | :? RsaPublicKey as otherPubKey ->
                (this :> IEquatable<RsaPublicKey>).Equals otherPubKey
            | _ -> false

    override this.GetHashCode() =
        HashCode.Combine(
            RsaPublicKey.SshRsa,
            (exponent :> System.Collections.IStructuralEquatable).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            (modulus :> System.Collections.IStructuralEquatable).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            comment)

type Ed25519PublicKey(key:byte array, comment:string) =
    inherit PublicKey(Ed25519PublicKey.SshEd25519, comment)
    /// Represents the identifier for Ed25519 algorithm in the context
    /// of SSH public key operations. The value is a literal string
    /// "ssh-ed25519", which is used to specify the Edwards Curve 25519
    /// with SHA-512 algorithm in SSH key exchanges and related operations.
    static member SshEd25519 = "ssh-ed25519"

    /// Represents the exponent value of a public ED25519 key as a byte array.
    ///
    /// The key is a critical component of the Ed25519 public key used
    /// in cryptographic algorithms. This property provides read-only
    /// access to the exponent value stored in the `PublicKey` instance.
    member val Key: byte array = key with get

    /// Represents an SSH public key with Ed25519 algorithm and associated parameters.
    ///
    /// Properties:
    /// - Algorithm: Represents the type of the algorithm (e.g., "ssh-ed25519").
    /// - Key: The public key of the Ed25519 key.
    /// - Comment: An optional comment associated with the public key.
    new(key) = Ed25519PublicKey(key, null)

    override this.WritePublicKeyComponents (sshBuf:SshBuffer) =
        this.Key |> sshBuf.WriteSshData

    interface IEquatable<Ed25519PublicKey> with
        member this.Equals (other: Ed25519PublicKey) =
            this.Algorithm = other.Algorithm &&
            System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(this.Key, other.Key) &&
            this.Comment = other.Comment

    override this.Equals(other) =
        if Object.ReferenceEquals(this,other) then true
        else
            match other with
            | :? Ed25519PublicKey as otherPubKey ->
                (this :> IEquatable<Ed25519PublicKey>).Equals otherPubKey
            | _ -> false

    override this.GetHashCode() =
        HashCode.Combine(
            Ed25519PublicKey.SshEd25519,
            (key :> System.Collections.IStructuralEquatable).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            comment)

type PublicKey with
    /// Parses an SSH public key from its string representation.
    ///
    /// This function processes a string representation of an SSH public key,
    /// extracting its algorithm name, base64-encoded key data, and an optional
    /// comment. It validates that the provided string format adheres to the SSH
    /// public key standard. If the string contains sufficient valid information,
    /// an instance of the `PublicKey` is returned.
    ///
    /// Parameters:
    /// - `keyLine`: A string representation of the SSH public key,
    ///   typically in the form `<algorithm> <base64-key-data> [optional-comment]`.
    ///
    /// Returns:
    /// - An instance of the `PublicKey` class initialized with the parsed key
    ///   data and optional comment.
    ///
    /// Exceptions:
    /// - `System.ArgumentException`: Thrown when keyLine is null or empty.
    /// - `System.FormatException`: Thrown when the key string is not properly
    ///   formatted, when base64 decoding fails, when the algorithm in the key
    ///   line doesn't match the algorithm in the embedded data, or when the
    ///   algorithm is not supported (currently only 'ssh-rsa' is supported).
    ///
    /// Assumptions:
    /// - The key string follows the standard SSH public key format.
    static member ParseSshPublicKey (keyLine:string) : PublicKey =
        if String.IsNullOrEmpty keyLine then
            invalidArg "keyLine" "Empty OpenSSH public key passed."
        // Plain SSH key line is ~400 characters, so 10,000 is a sane maximum.
        if keyLine.Length > 10_000 then
            raise (FormatException "Oversized OpenSSH public key line")            
        let sections = keyLine.Split ([|' '|], StringSplitOptions.RemoveEmptyEntries)
        if sections.Length > 1 then
            let algName = sections[0]
            let b64data = sections[1]
            let data = b64data |> Convert.FromBase64String
            use ms = new MemoryStream(data)
            let sshBuf = SshBuffer(ms)
            let alg = sshBuf.ReadSshData() |> Encoding.UTF8.GetString
            
            // Validate that the algorithm in the key line matches the embedded algorithm
            if algName <> alg then
                raise (FormatException (String.Format("Algorithm mismatch: key line specifies '{0}' but embedded data contains '{1}'", algName, alg)))
            
            // Validate that we support this algorithm
            if alg = RsaPublicKey.SshRsa then
                let e = sshBuf.ReadSshData()
                let n = sshBuf.ReadSshData()
                if sections.Length > 2 then
                    RsaPublicKey(e, n, String.Join(' ', sections[2..])) // key comment.
                else
                    RsaPublicKey(e, n)
            elif alg = Ed25519PublicKey.SshEd25519 then
                let k = sshBuf.ReadSshData()
                if sections.Length > 2 then
                    Ed25519PublicKey(k, String.Join(' ', sections[2..])) // key comment.
                else
                    Ed25519PublicKey(k)
            else
                raise (FormatException (String.Format("Unsupported algorithm '{0}'. Only '{1} and {2}' are currently supported.", alg, RsaPublicKey.SshRsa, Ed25519PublicKey.SshEd25519)))
        else
            raise (FormatException "Malformed OpenSSH public key line.")

    /// Converts a `PublicKey` instance into its SSH public key string representation.
    ///
    /// The output format adheres to the standard OpenSSH format:
    /// `<algorithm> <base64-encoded-key-bytes> <optional-comment>`.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the algorithm, exponent, modulus, and optional comment.
    ///
    /// Returns:
    ///   A string in the SSH public key format.
    static member ToSshPublicKey (pubKey:PublicKey) =
        pubKey.AsSshPublicKey

    /// Converts a `PublicKey` instance into a 'cert-authority' line ready for adding to an 'authorized_keys' file.
    ///
    /// The output format adheres to the standard OpenSSH format:
    /// `cert-authority <algorithm> <base64-encoded-key-bytes> <optional-comment>`.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the algorithm, exponent, modulus, and optional comment.
    ///
    /// Returns:
    ///   A cert-authhority line containing the SSH public key for use in an 'authorized_keys' file.
    static member ToSshCertAuthority (pubKey:PublicKey) =
        String.Concat ("cert-authority ", pubKey.AsSshPublicKey)

    /// Parses a PEM-encoded RSA public key string and a comment to an internal
    /// representation suitable for working with SSH-compatible RSA parameters.
    ///
    /// The function imports the RSA public key from a PEM-encoded string, extracts
    /// the parameters such as modulus and exponent, and applies a technique to
    /// ensure the modulus is properly formatted for OpenSSH compatibility. Specifically,
    /// it ensures the most significant bit (MSB) of the modulus is positive.
    ///
    /// Parameters:
    /// - `pem`: A PEM-encoded RSA public key string.
    /// - `comment`: An optional comment to associate with the public key.
    ///
    /// Returns:
    /// - An instance of the `PublicKey` class initialized with the parsed key data.
    ///
    /// Exceptions:
    /// - `System.ArgumentException`: Thrown when the PEM string is null or empty.
    /// - `System.Security.Cryptography.CryptographicException`: Thrown when the PEM format is invalid.
    static member ParseRsaPublicKeyPem (pem:string, comment:string) =
        if String.IsNullOrEmpty pem then
            invalidArg "pem" "Empty RSA public key PEM passed."
        use rsa = RSA.Create()
        rsa.ImportFromPem(pem)
        let exported = rsa.ExportParameters(false)
        // RSA can generate a modulus with MSB set (so negative) but openssh doesn't like this.
        // It does allow a prepended '\0' (NULL) that will force the MSB to be positive. It then trims this
        // NULL so it becomes the same modulus as before. Using that same technique here.
        let forcePosMod =
            if (exported.Modulus[0] &&& 128uy) <> 0uy then
                let result : byte array = Array.CreateInstance(typeof<byte>, exported.Modulus.Length + 1) :?> byte array
                Array.Copy(exported.Modulus, 0, result, 1, exported.Modulus.Length)
                result
            else exported.Modulus
        RsaPublicKey(exported.Exponent, forcePosMod, comment)

    /// Parses a PEM-encoded RSA public key string to an internal representation
    /// suitable for working with SSH-compatible RSA parameters.
    ///
    /// The function imports the RSA public key from a PEM-encoded string, extracts
    /// the parameters such as modulus and exponent, and applies a technique to
    /// ensure the modulus is properly formatted for OpenSSH compatibility. Specifically,
    /// it ensures the most significant bit (MSB) of the modulus is positive.
    ///
    /// Parameters:
    /// - `pem`: A PEM-encoded RSA public key string.
    ///
    /// Returns:
    /// - An instance of the `PublicKey` class initialized with the parsed key data.
    ///
    /// Exceptions:
    /// - `System.ArgumentException`: Thrown when the PEM string is null or empty.
    /// - `System.Security.Cryptography.CryptographicException`: Thrown when the PEM format is invalid.
    static member ParseRsaPublicKeyPem (pem:string) =
        PublicKey.ParseRsaPublicKeyPem(pem, null)

    /// Attempts to parse an SSH public key from its string representation without throwing exceptions.
    ///
    /// This is a safer alternative to `ParseSshPublicKey` that returns a boolean indicating success
    /// rather than throwing exceptions on parse failures.
    ///
    /// Parameters:
    /// - `keyLine`: A string representation of the SSH public key,
    ///   typically in the form `<algorithm> <base64-key-data> [optional-comment]`.
    /// - `publicKey`: When this method returns, contains the parsed `PublicKey` if successful,
    ///   or null if parsing failed.
    ///
    /// Returns:
    /// - `true` if the key was successfully parsed; otherwise, `false`.
    static member TryParseSshPublicKey (keyLine:string, [<Out>] publicKey:byref<PublicKey>) =
        try
            publicKey <- PublicKey.ParseSshPublicKey(keyLine)
            true
        with
        | _ ->
            publicKey <- null
            false

    /// Attempts to parse a PEM-encoded RSA public key without throwing exceptions.
    ///
    /// This is a safer alternative to `ParseRsaPublicKeyPem` that returns a boolean indicating success
    /// rather than throwing exceptions on parse failures.
    ///
    /// Parameters:
    /// - `pem`: A PEM-encoded RSA public key string.
    /// - `comment`: An optional comment to associate with the public key.
    /// - `publicKey`: When this method returns, contains the parsed `PublicKey` if successful,
    ///   or null if parsing failed.
    ///
    /// Returns:
    /// - `true` if the key was successfully parsed; otherwise, `false`.
    static member TryParseRsaPublicKeyPem (pem:string, comment:string, [<Out>] publicKey:byref<PublicKey>) =
        try
            publicKey <- PublicKey.ParseRsaPublicKeyPem(pem, comment)
            true
        with
        | _ ->
            publicKey <- null
            false

    /// Attempts to parse a PEM-encoded RSA public key without throwing exceptions.
    ///
    /// This is a safer alternative to `ParseRsaPublicKeyPem` that returns a boolean indicating success
    /// rather than throwing exceptions on parse failures.
    ///
    /// Parameters:
    /// - `pem`: A PEM-encoded RSA public key string.
    /// - `publicKey`: When this method returns, contains the parsed `PublicKey` if successful,
    ///   or null if parsing failed.
    ///
    /// Returns:
    /// - `true` if the key was successfully parsed; otherwise, `false`.
    static member TryParseRsaPublicKeyPem (pem:string, [<Out>] publicKey:byref<PublicKey>) =
        PublicKey.TryParseRsaPublicKeyPem(pem, null, &publicKey)

    /// Parses an SSH public key from its string representation.
    /// <remarks>This method is deprecated. Use <see cref="ParseSshPublicKey"/> instead.</remarks>
    [<System.Obsolete("OfSshPublicKey is deprecated. Use ParseSshPublicKey(string) instead for better .NET naming consistency.", false)>]
    static member OfSshPublicKey (keyLine:string) =
        PublicKey.ParseSshPublicKey(keyLine)

    /// Parses a PEM-encoded RSA public key with an optional comment.
    /// <remarks>This method is deprecated. Use <see cref="ParseRsaPublicKeyPem"/> instead.</remarks>
    [<System.Obsolete("OfRsaPublicKeyPem is deprecated. Use ParseRsaPublicKeyPem(string, string) instead for better .NET naming consistency.", false)>]
    static member OfRsaPublicKeyPem (pem:string, comment:string) =
        PublicKey.ParseRsaPublicKeyPem(pem, comment)

    /// Parses a PEM-encoded RSA public key.
    /// <remarks>This method is deprecated. Use <see cref="ParseRsaPublicKeyPem"/> instead.</remarks>
    [<System.Obsolete("OfRsaPublicKeyPem is deprecated. Use ParseRsaPublicKeyPem(string) instead for better .NET naming consistency.", false)>]
    static member OfRsaPublicKeyPem (pem:string) =
        PublicKey.ParseRsaPublicKeyPem(pem)

    /// Converts a `PublicKey` to an RSA public key represented as an `RSA` object.
    /// This function uses the `Exponent` and `Modulus` properties of the given `PublicKey`
    /// to create an `RSAParameters` structure, which is then used to initialize the RSA instance.
    ///
    /// Be sure to dispose of this RSA instance after use.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the RSA exponent and modulus.
    ///
    /// Returns:
    ///   An `RSA` object initialized with the specified public key parameters.
    static member ToRsaPublicKey (pubKey:PublicKey) =
        match pubKey with
        | :? RsaPublicKey as rsaPublicKey ->
            RSA.Create(RSAParameters(Exponent=rsaPublicKey.Exponent, Modulus=rsaPublicKey.Modulus))
        | _ -> invalidOp (String.Format ("Cannot convert {0} public key to RSA.", pubKey.Algorithm))
