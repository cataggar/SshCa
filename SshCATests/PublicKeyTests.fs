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
module PublicKeyTests

open System
open System.Collections.Generic
open System.Security.Cryptography
open Expecto
open SshCA
open TestData

[<Tests>]
let tests =
    testList "Public Key Tests" [
        test "Parse OpenSSH RSA Public Key File" {
            let publicKey = PublicKey.ParseSshPublicKey testRsaSshKey :?> RsaPublicKey
            Expect.equal
                publicKey.Algorithm
                "ssh-rsa"
                "Incorrect algorithm"
            Expect.equal
                (publicKey.Exponent |> Convert.ToHexString)
                "010001"
                "Incorrect exponent"
            Expect.equal
                (publicKey.Modulus |> Convert.ToHexString)
                "00D233CA5C8CFE24294C63F82434E49D0D2F47992A1DBB59D41123100A178B17546327EE2145B79208764EA63B5305EA06DE52CB96CB68F6B6624CC385865A15FF36D8D0C5F814904A9257651AA1291097395E20B462DDBFDBBACC74C7113956BD577058A63879750638522A88CC6B46AAC3D121CFB44DAA042669F2C7B199922C695759044F31EA74B385FFC3646CB57249FA1F0F8736DA8CF0F3558E790E21BB5DD3BBC1AC4845E175A751020E48DC8D58B9B2A8F48E99E2D1299D14CEBD86CAC87D31A16CC83EF5FFAC15DBEC92452D1BAC4F393EC61E5F856582D0E139C00D6433FE90EF4526AB8370A59880BDFD8D3488125970334356B939B68E536EEFAC4002656195B2E8E692D02AC05321C52F564105614E77C7616ADAF498933E88DACB42C400E9D6862A600F05227621C8A4882A5CA89D7BF517DF39B3A3EFD58F6E999632B5B9798AA2F0AB2CA99A8E2B5E520D0B603A7386CA7071647C61DD0D87C2F681156EAF05DA94865F3B116B30EF116A9564AE292C6323B18CDC547074EF"
                $"Incorrect modulus"
            Expect.isNotNull publicKey.Comment "OpenSSH key should have comment."
            Expect.equal
                publicKey.Comment
                "user@domain.local"
                "Incorrect comment"
        }
        test "Parse OpenSSH Ed25519 Public Key File" {
            let publicKey = PublicKey.ParseSshPublicKey testEd25519SshKey :?> Ed25519PublicKey
            Expect.equal
                publicKey.Algorithm
                "ssh-ed25519"
                "Incorrect algorithm"
            Expect.equal
                (publicKey.Key |> Convert.ToHexString)
                "7740D78D35F10DCD2ECA9DBEBF25D088E3565A17D792622FB72F752C9681F293"
                $"Incorrect modulus"
            Expect.isNotNull publicKey.Comment "OpenSSH key should have comment."
            Expect.equal
                publicKey.Comment
                "user@domain.local"
                "Incorrect comment"
        }
        test "Parse OpenSSH Public Key - Long Comment" {
            let publicKey = testSshKeyWithLongComment |> PublicKey.ParseSshPublicKey :?> RsaPublicKey
            Expect.equal
                (publicKey.Exponent |> Convert.ToHexString)
                "010001"
                "Incorrect exponent"
            Expect.equal // Modulus from RSA will not have 0 (NULL) byte at the beginning that the ssh key does.
                (publicKey.Modulus |> Convert.ToHexString)
                "00D233CA5C8CFE24294C63F82434E49D0D2F47992A1DBB59D41123100A178B17546327EE2145B79208764EA63B5305EA06DE52CB96CB68F6B6624CC385865A15FF36D8D0C5F814904A9257651AA1291097395E20B462DDBFDBBACC74C7113956BD577058A63879750638522A88CC6B46AAC3D121CFB44DAA042669F2C7B199922C695759044F31EA74B385FFC3646CB57249FA1F0F8736DA8CF0F3558E790E21BB5DD3BBC1AC4845E175A751020E48DC8D58B9B2A8F48E99E2D1299D14CEBD86CAC87D31A16CC83EF5FFAC15DBEC92452D1BAC4F393EC61E5F856582D0E139C00D6433FE90EF4526AB8370A59880BDFD8D3488125970334356B939B68E536EEFAC4002656195B2E8E692D02AC05321C52F564105614E77C7616ADAF498933E88DACB42C400E9D6862A600F05227621C8A4882A5CA89D7BF517DF39B3A3EFD58F6E999632B5B9798AA2F0AB2CA99A8E2B5E520D0B603A7386CA7071647C61DD0D87C2F681156EAF05DA94865F3B116B30EF116A9564AE292C6323B18CDC547074EF"
                "Incorrect modulus"
            Expect.equal
                publicKey.Comment
                "user@domain.local comment can be many words"
                "Incorrect comment"
        }
        test "Parse PEM Public Key File" {
            let publicKey = testSshKeyPem |> PublicKey.ParseRsaPublicKeyPem
            Expect.equal
                (publicKey.Exponent |> Convert.ToHexString)
                "010001"
                "Incorrect exponent"
            Expect.equal // Modulus from RSA will not have 0 (NULL) byte at the beginning that the ssh key does.
                (publicKey.Modulus |> Convert.ToHexString)
                "00D233CA5C8CFE24294C63F82434E49D0D2F47992A1DBB59D41123100A178B17546327EE2145B79208764EA63B5305EA06DE52CB96CB68F6B6624CC385865A15FF36D8D0C5F814904A9257651AA1291097395E20B462DDBFDBBACC74C7113956BD577058A63879750638522A88CC6B46AAC3D121CFB44DAA042669F2C7B199922C695759044F31EA74B385FFC3646CB57249FA1F0F8736DA8CF0F3558E790E21BB5DD3BBC1AC4845E175A751020E48DC8D58B9B2A8F48E99E2D1299D14CEBD86CAC87D31A16CC83EF5FFAC15DBEC92452D1BAC4F393EC61E5F856582D0E139C00D6433FE90EF4526AB8370A59880BDFD8D3488125970334356B939B68E536EEFAC4002656195B2E8E692D02AC05321C52F564105614E77C7616ADAF498933E88DACB42C400E9D6862A600F05227621C8A4882A5CA89D7BF517DF39B3A3EFD58F6E999632B5B9798AA2F0AB2CA99A8E2B5E520D0B603A7386CA7071647C61DD0D87C2F681156EAF05DA94865F3B116B30EF116A9564AE292C6323B18CDC547074EF"
                $"Incorrect modulus"
        }
        test "RSA to OpenSSH" {
            let exponent = Convert.FromHexString "010001"
            let modulus = Convert.FromHexString "9CBFEA68EE2BAE92903BCD8296718E680C4D34928E05C3EB185861BBAA051E57523399FB443EBC04F963A53A623B42959BD1E6F06DFA240C12BEC0EECBF5C4953DFA7F016F46271C1C127353F6E3D314A25176819EFFB581DDB6D559908EABFD1CC95709FCEA28C213C7202DD506924A1E57C4F20F08B15FEB1A20B0B78F1066223A1AE5C60C539B824A52DF2C5364EAD4E0780D646EDA78012C9B7E0E10EFA6DA9AC9CC86044C0110232B795C5BD8E36E83607611B572E468A19888A1A65278F90BDD820BE29982EDD53560569F34AB946A92A131C1F9248CB3FD3FCD8B4C2AAF69951930902579DED1A8E1143BEFB2047638D9A7B1F3AA72A41070F297337F"
            let parameters = RSAParameters(Exponent=exponent, Modulus=modulus)
            use rsa = RSA.Create(parameters)
            let publicKey = rsa.ExportRSAPublicKeyPem() |> PublicKey.ParseRsaPublicKeyPem
            let sshKey = publicKey |> PublicKey.ToSshPublicKey
            Expect.equal
                sshKey
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcv+po7iuukpA7zYKWcY5oDE00ko4Fw+sYWGG7qgUeV1IzmftEPrwE+WOlOmI7QpWb0ebwbfokDBK+wO7L9cSVPfp/AW9GJxwcEnNT9uPTFKJRdoGe/7WB3bbVWZCOq/0cyVcJ/OoowhPHIC3VBpJKHlfE8g8IsV/rGiCwt48QZiI6GuXGDFObgkpS3yxTZOrU4HgNZG7aeAEsm34OEO+m2prJzIYETAEQIyt5XFvY426DYHYRtXLkaKGYiKGmUnj5C92CC+KZgu3VNWBWnzSrlGqSoTHB+SSMs/0/zYtMKq9plRkwkCV53tGo4RQ777IEdjjZp7HzqnKkEHDylzN/"
                "Generated SSH key did not match expected."
        }
        test "ED25519 to OpenSSH" {
            let exponent = Convert.FromHexString "010001"
            let modulus = Convert.FromHexString "9CBFEA68EE2BAE92903BCD8296718E680C4D34928E05C3EB185861BBAA051E57523399FB443EBC04F963A53A623B42959BD1E6F06DFA240C12BEC0EECBF5C4953DFA7F016F46271C1C127353F6E3D314A25176819EFFB581DDB6D559908EABFD1CC95709FCEA28C213C7202DD506924A1E57C4F20F08B15FEB1A20B0B78F1066223A1AE5C60C539B824A52DF2C5364EAD4E0780D646EDA78012C9B7E0E10EFA6DA9AC9CC86044C0110232B795C5BD8E36E83607611B572E468A19888A1A65278F90BDD820BE29982EDD53560569F34AB946A92A131C1F9248CB3FD3FCD8B4C2AAF69951930902579DED1A8E1143BEFB2047638D9A7B1F3AA72A41070F297337F"
            let parameters = RSAParameters(Exponent=exponent, Modulus=modulus)
            use rsa = RSA.Create(parameters)
            let key = Convert.FromHexString "89a429c70941937ebeb071b8c5def2aadd41bfc87f7098b40283b77b2c5e7a5f"
            let publicKey = Ed25519PublicKey(key)
            let sshKey = publicKey |> PublicKey.ToSshPublicKey
            Expect.equal
                sshKey
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImkKccJQZN+vrBxuMXe8qrdQb/If3CYtAKDt3ssXnpf"
                "Generated SSH key did not match expected."
        }
        test "RSA to OpenSSH cert-authority line" {
            let publicKey =
                let exponent = Convert.FromHexString "010001"
                let modulus = Convert.FromHexString "9CBFEA68EE2BAE92903BCD8296718E680C4D34928E05C3EB185861BBAA051E57523399FB443EBC04F963A53A623B42959BD1E6F06DFA240C12BEC0EECBF5C4953DFA7F016F46271C1C127353F6E3D314A25176819EFFB581DDB6D559908EABFD1CC95709FCEA28C213C7202DD506924A1E57C4F20F08B15FEB1A20B0B78F1066223A1AE5C60C539B824A52DF2C5364EAD4E0780D646EDA78012C9B7E0E10EFA6DA9AC9CC86044C0110232B795C5BD8E36E83607611B572E468A19888A1A65278F90BDD820BE29982EDD53560569F34AB946A92A131C1F9248CB3FD3FCD8B4C2AAF69951930902579DED1A8E1143BEFB2047638D9A7B1F3AA72A41070F297337F"
                let parameters = RSAParameters(Exponent=exponent, Modulus=modulus)
                use rsa = RSA.Create(parameters)
                let pem = rsa.ExportRSAPublicKeyPem()
                PublicKey.ParseRsaPublicKeyPem (pem, "my-cert-auth-info")
            let certAuth = publicKey |> PublicKey.ToSshCertAuthority
            Expect.equal
                certAuth
                "cert-authority ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcv+po7iuukpA7zYKWcY5oDE00ko4Fw+sYWGG7qgUeV1IzmftEPrwE+WOlOmI7QpWb0ebwbfokDBK+wO7L9cSVPfp/AW9GJxwcEnNT9uPTFKJRdoGe/7WB3bbVWZCOq/0cyVcJ/OoowhPHIC3VBpJKHlfE8g8IsV/rGiCwt48QZiI6GuXGDFObgkpS3yxTZOrU4HgNZG7aeAEsm34OEO+m2prJzIYETAEQIyt5XFvY426DYHYRtXLkaKGYiKGmUnj5C92CC+KZgu3VNWBWnzSrlGqSoTHB+SSMs/0/zYtMKq9plRkwkCV53tGo4RQ777IEdjjZp7HzqnKkEHDylzN/ my-cert-auth-info"
                "Generated cert-authority line did not match expected."
        }
        test "OpenSSH to string" {
            let exponent = Convert.FromHexString "010001"
            let modulus = Convert.FromHexString "00589318A110562B4171EE69A3D2CA79C9FFF9B0608CA2E89472BC4ADE672DD4DDCC7515FBD53403FD2F32DC0749110D9C6461BE057F81B436ADEB6DA4A8B4DC641D85DFB077A19482AD55EFA996AC2A488FC0896A35FFB6D31ED5B306084FBF7DAA8A510773CBF6CF3E470013FA3F7E2A618CC7978F5B3680AE146126CCF61385D8109822521B46A478E73E1090791706A4581D04F621BF9F7C13D6B20EDAFC236C17CBD3E2BF93EE8AFA6530334EF49C893CE584390FC6260F26AA3610FFCCAF428D729D4814E73272157D64E6EB6FD74B3216BC998D299054A4A6F3629CCEAA52B141A4128F4F7FCB6B82A25AA84D139C4E4C68E3DE0CA7C100DB7ED7A5A2"
            let sshKey = RsaPublicKey(exponent, modulus, "test@example.local").ToString()
            Expect.equal
                sshKey
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAABYkxihEFYrQXHuaaPSynnJ//mwYIyi6JRyvEreZy3U3cx1FfvVNAP9LzLcB0kRDZxkYb4Ff4G0Nq3rbaSotNxkHYXfsHehlIKtVe+plqwqSI/AiWo1/7bTHtWzBghPv32qilEHc8v2zz5HABP6P34qYYzHl49bNoCuFGEmzPYThdgQmCJSG0akeOc+EJB5FwakWB0E9iG/n3wT1rIO2vwjbBfL0+K/k+6K+mUwM070nIk85YQ5D8YmDyaqNhD/zK9CjXKdSBTnMnIVfWTm62/XSzIWvJmNKZBUpKbzYpzOqlKxQaQSj09/y2uColqoTROcTkxo494Mp8EA237XpaI= test@example.local"
                "Generated SSH key did not match expected."
        }
        test "OpenSSH to RSA" {
            let publicKey = PublicKey.ParseSshPublicKey testRsaSshKey
            use rsa = publicKey |> PublicKey.ToRsaPublicKey
            let rsaPubKey = rsa.ExportParameters(false)
            Expect.equal
                (rsaPubKey.Exponent |> Convert.ToHexString)
                "010001"
                "Incorrect exponent"
            Expect.equal // Modulus from RSA will not have 0 (NULL) byte at the beginning that the ssh key does.
                (rsaPubKey.Modulus |> Convert.ToHexString)
                "D233CA5C8CFE24294C63F82434E49D0D2F47992A1DBB59D41123100A178B17546327EE2145B79208764EA63B5305EA06DE52CB96CB68F6B6624CC385865A15FF36D8D0C5F814904A9257651AA1291097395E20B462DDBFDBBACC74C7113956BD577058A63879750638522A88CC6B46AAC3D121CFB44DAA042669F2C7B199922C695759044F31EA74B385FFC3646CB57249FA1F0F8736DA8CF0F3558E790E21BB5DD3BBC1AC4845E175A751020E48DC8D58B9B2A8F48E99E2D1299D14CEBD86CAC87D31A16CC83EF5FFAC15DBEC92452D1BAC4F393EC61E5F856582D0E139C00D6433FE90EF4526AB8370A59880BDFD8D3488125970334356B939B68E536EEFAC4002656195B2E8E692D02AC05321C52F564105614E77C7616ADAF498933E88DACB42C400E9D6862A600F05227621C8A4882A5CA89D7BF517DF39B3A3EFD58F6E999632B5B9798AA2F0AB2CA99A8E2B5E520D0B603A7386CA7071647C61DD0D87C2F681156EAF05DA94865F3B116B30EF116A9564AE292C6323B18CDC547074EF"
                $"Incorrect modulus"
        }
        test "Equality tests" {
            let pubKey = RsaPublicKey([|1uy;2uy|], [|3uy;4uy;5uy|], "test@example.com")
            let samePubKey = RsaPublicKey([|1uy;2uy|], [|3uy;4uy;5uy|], "test@example.com")
            let differentPubKey = RsaPublicKey([|5uy;4uy|], [|3uy;2uy;1uy|], "test@example.com")
            Expect.isTrue
                (pubKey = samePubKey)
                "Same public keys are equal"
            Expect.isFalse
                (pubKey = differentPubKey)
                "Different public keys are not equal"
        }
        test "Hashcode tests" {
            let pubKey = RsaPublicKey([|1uy;2uy|], [|3uy;4uy;5uy|], "test@example.com")
            let samePubKey = RsaPublicKey([|1uy;2uy|], [|3uy;4uy;5uy|], "test@example.com")
            let differentPubKey = RsaPublicKey([|5uy;4uy|], [|3uy;2uy;1uy|], "test@example.com")
            let set = HashSet()
            Expect.isTrue
                (set.Add(pubKey))
                "PubKey should be newly added"
            Expect.isFalse
                (set.Add(samePubKey))
                "Same pubKey should be existing"
            Expect.isTrue
                (set.Add(differentPubKey))
                "Different pubKey should be newly added"
        }
        test "TryParse SSH RSA Public Key - Success" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseSshPublicKey(testRsaSshKey, &publicKey)
            Expect.isTrue success "Should successfully parse valid SSH key"
            Expect.isNotNull publicKey "Public key should not be null"
            Expect.equal publicKey.Algorithm "ssh-rsa" "Incorrect algorithm"
            Expect.equal publicKey.Comment "user@domain.local" "Incorrect comment"
            match publicKey with
            | :? RsaPublicKey as rsaPubKey ->
                Expect.equal
                    (rsaPubKey.Exponent |> Convert.ToHexString)
                    "010001"
                    "Incorrect exponent"
            | _ -> failtest "Expected RsaPublicKey"
        }
        test "TryParse SSH Public Key - Invalid input" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseSshPublicKey("invalid-key-data", &publicKey)
            Expect.isFalse success "Should fail to parse invalid SSH key"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "TryParse SSH Public Key - Empty input" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseSshPublicKey("", &publicKey)
            Expect.isFalse success "Should fail to parse empty string"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "TryParse SSH Public Key - Null input" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseSshPublicKey(null, &publicKey)
            Expect.isFalse success "Should fail to parse null string"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "TryParse SSH Public Key - Oversized input" {
            let mutable publicKey : PublicKey = null
            let oversizedKey = String('x', 20_000)
            let success = PublicKey.TryParseSshPublicKey(oversizedKey, &publicKey)
            Expect.isFalse success "Should fail to parse oversized key"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "TryParse RSA Public Key PEM - Success" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseRsaPublicKeyPem(testSshKeyPem, &publicKey)
            Expect.isTrue success "Should successfully parse valid PEM"
            Expect.isNotNull publicKey "Public key should not be null"
            match publicKey with
            | :? RsaPublicKey as rsaPubKey ->
                Expect.equal
                    (rsaPubKey.Exponent |> Convert.ToHexString)
                    "010001"
                    "Incorrect exponent"
            | _ -> failtest "Expected RsaPublicKey"
        }
        test "TryParse RSA Public Key PEM with comment - Success" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseRsaPublicKeyPem(testSshKeyPem, "test-comment", &publicKey)
            Expect.isTrue success "Should successfully parse valid PEM with comment"
            Expect.isNotNull publicKey "Public key should not be null"
            Expect.equal publicKey.Comment "test-comment" "Incorrect comment"
        }
        test "TryParse RSA Public Key PEM - Invalid input" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseRsaPublicKeyPem("not-a-pem-key", &publicKey)
            Expect.isFalse success "Should fail to parse invalid PEM"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "TryParse RSA Public Key PEM - Empty input" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseRsaPublicKeyPem("", &publicKey)
            Expect.isFalse success "Should fail to parse empty string"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "TryParse RSA Public Key PEM - Null input" {
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseRsaPublicKeyPem(null, &publicKey)
            Expect.isFalse success "Should fail to parse null string"
            Expect.isNull publicKey "Public key should be null on failure"
        }
        test "Parse SSH Public Key - Algorithm validation detects mismatch" {
            // Create a malformed key where the algorithm prefix doesn't match the embedded data
            // This is a real ssh-rsa key, but we'll modify the prefix
            let malformedKey = testRsaSshKey.Replace("ssh-rsa", "ssh-ed25519")
            
            Expect.throws
                (fun () -> PublicKey.ParseSshPublicKey(malformedKey) |> ignore)
                "Should throw FormatException for algorithm mismatch"
        }
        test "TryParse detects algorithm mismatch" {
            let malformedKey = testRsaSshKey.Replace("ssh-rsa", "ssh-ed25519")
            let mutable publicKey : PublicKey = null
            let success = PublicKey.TryParseSshPublicKey(malformedKey, &publicKey)
            Expect.isFalse success "Should fail to parse key with algorithm mismatch"
            Expect.isNull publicKey "Public key should be null on failure"
        }
    ]
