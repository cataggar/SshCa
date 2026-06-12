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
module TestData

let testRsaSshKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSM8pcjP4kKUxj+CQ05J0NL0eZKh27WdQRIxAKF4sXVGMn7iFFt5IIdk6mO1MF6gbeUsuWy2j2tmJMw4WGWhX/NtjQxfgUkEqSV2UaoSkQlzleILRi3b/busx0xxE5Vr1XcFimOHl1BjhSKojMa0aqw9Ehz7RNqgQmafLHsZmSLGlXWQRPMep0s4X/w2RstXJJ+h8PhzbajPDzVY55DiG7XdO7waxIReF1p1ECDkjcjVi5sqj0jpni0SmdFM69hsrIfTGhbMg+9f+sFdvskkUtG6xPOT7GHl+FZYLQ4TnADWQz/pDvRSarg3ClmIC9/Y00iBJZcDNDVrk5to5Tbu+sQAJlYZWy6OaS0CrAUyHFL1ZBBWFOd8dhatr0mJM+iNrLQsQA6daGKmAPBSJ2IcikiCpcqJ179RffObOj79WPbpmWMrW5eYqi8KssqZqOK15SDQtgOnOGynBxZHxh3Q2HwvaBFW6vBdqUhl87EWsw7xFqlWSuKSxjI7GM3FRwdO8= user@domain.local"
let testEd25519SshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHdA14018Q3NLsqdvr8l0IjjVloX15JiL7cvdSyWgfKT user@domain.local"
let testSshKeyWithLongComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSM8pcjP4kKUxj+CQ05J0NL0eZKh27WdQRIxAKF4sXVGMn7iFFt5IIdk6mO1MF6gbeUsuWy2j2tmJMw4WGWhX/NtjQxfgUkEqSV2UaoSkQlzleILRi3b/busx0xxE5Vr1XcFimOHl1BjhSKojMa0aqw9Ehz7RNqgQmafLHsZmSLGlXWQRPMep0s4X/w2RstXJJ+h8PhzbajPDzVY55DiG7XdO7waxIReF1p1ECDkjcjVi5sqj0jpni0SmdFM69hsrIfTGhbMg+9f+sFdvskkUtG6xPOT7GHl+FZYLQ4TnADWQz/pDvRSarg3ClmIC9/Y00iBJZcDNDVrk5to5Tbu+sQAJlYZWy6OaS0CrAUyHFL1ZBBWFOd8dhatr0mJM+iNrLQsQA6daGKmAPBSJ2IcikiCpcqJ179RffObOj79WPbpmWMrW5eYqi8KssqZqOK15SDQtgOnOGynBxZHxh3Q2HwvaBFW6vBdqUhl87EWsw7xFqlWSuKSxjI7GM3FRwdO8= user@domain.local comment can be many words"
let testSshKeyPem = """-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEA0jPKXIz+JClMY/gkNOSdDS9HmSodu1nUESMQCheLF1RjJ+4hRbeS
CHZOpjtTBeoG3lLLlsto9rZiTMOFhloV/zbY0MX4FJBKkldlGqEpEJc5XiC0Yt2/
27rMdMcROVa9V3BYpjh5dQY4UiqIzGtGqsPRIc+0TaoEJmnyx7GZkixpV1kETzHq
dLOF/8NkbLVySfofD4c22ozw81WOeQ4hu13Tu8GsSEXhdadRAg5I3I1YubKo9I6Z
4tEpnRTOvYbKyH0xoWzIPvX/rBXb7JJFLRusTzk+xh5fhWWC0OE5wA1kM/6Q70Um
q4NwpZiAvf2NNIgSWXAzQ1a5ObaOU27vrEACZWGVsujmktAqwFMhxS9WQQVhTnfH
YWra9JiTPojay0LEAOnWhipgDwUidiHIpIgqXKide/UX3zmzo+/Vj26ZljK1uXmK
ovCrLKmajiteUg0LYDpzhspwcWR8Yd0Nh8L2gRVurwXalIZfOxFrMO8RapVkriks
YyOxjNxUcHTvAgMBAAE=
-----END RSA PUBLIC KEY-----"""
let nonce = Array.zeroCreate<byte> 32

let certValidationOutput = """
        Key ID: "testkey"
        Serial: 0
        Valid: from 2025-06-13T08:00:00 to 2025-06-13T10:00:00
        Principals: 
                someUser
        Critical Options: (none)
        Extensions: (none)
"""