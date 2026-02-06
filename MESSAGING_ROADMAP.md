# Messaging & Social Media Roadmap

Features needed in `@dragbin/crypto` to support messaging and social media applications.

## Tier 1 — Must-have

### 1. Lightweight message encryption

The current `encryptFile` prepends a 10KB metadata header and chunks at 1KB. For chat messages this is excessive overhead. Need a compact API that does Kyber KEM + single AES-GCM encrypt with no chunking or padding.

```ts
encryptMessage(text: string, publicKey: Uint8Array)
  → { ciphertext: Uint8Array, encryptedSessionKey: Uint8Array }

decryptMessage(ciphertext: Uint8Array, encryptedSessionKey: Uint8Array, privateKey: Uint8Array)
  → string
```

**Files to modify:** new `src/message.ts`, update `src/index.ts` exports, add `test/message.test.ts`

---

### 2. Symmetric encrypt/decrypt (password-only mode)

For shared-secret chat rooms where everyone knows the password. No Kyber involved — just Argon2id key derivation + AES-GCM.

```ts
encryptSymmetric(data: Uint8Array, password: string, salt?: Uint8Array)
  → { ciphertext: Uint8Array, salt: Uint8Array, iv: Uint8Array }

decryptSymmetric(ciphertext: Uint8Array, password: string, salt: Uint8Array, iv: Uint8Array)
  → Uint8Array
```

**Files to modify:** new `src/symmetric.ts`, update `src/index.ts` exports, add `test/symmetric.test.ts`

---

### 3. Key serialization

Everything is raw `Uint8Array` currently. App developers need to store keys in databases, send over HTTP, put in JWTs. The `bytesToBase64`/`base64ToBytes` helpers exist in `utils.ts` but aren't exported.

```ts
exportKey(key: Uint8Array) → string
importKey(encoded: string) → Uint8Array
exportKeyPair(pair: KyberKeyPair) → { publicKey: string, privateKey: string }
importKeyPair(encoded: { publicKey: string, privateKey: string }) → KyberKeyPair
```

**Files to modify:** new `src/serialization.ts` or extend `src/utils.ts`, update `src/index.ts` exports, add tests

---

## Tier 2 — Important

### 4. Key fingerprinting

Users need to verify each other's identity — "does this public key belong to who I think it does?" SHA-256 hash of the public key, formatted for human comparison.

```ts
fingerprintKey(publicKey: Uint8Array) → string   // e.g. "A3F2 9B1C D4E8 ..."
compareFingerprints(a: string, b: string) → boolean
```

**Files to modify:** new `src/fingerprint.ts` or extend `src/utils.ts`, update `src/index.ts` exports, add tests

---

### 5. Multi-recipient encryption

Group chats. Encrypt a message once, N people can decrypt. Generate a random session key, encrypt the message with it, then Kyber-encapsulate that session key once per recipient.

```ts
encryptForGroup(data: Uint8Array, publicKeys: Uint8Array[])
  → { ciphertext: Uint8Array, encryptedKeys: Uint8Array[] }

decryptFromGroup(ciphertext: Uint8Array, encryptedKeys: Uint8Array[], myPrivateKey: Uint8Array, myIndex: number)
  → Uint8Array
```

**Files to modify:** new `src/group.ts`, update `src/index.ts` exports, add `test/group.test.ts`

---

### 6. Session / cached key derivation

Argon2id takes ~500ms. Can't pay that per message. Need a pattern to derive once at login and reuse for the session lifetime.

```ts
interface Session {
  decryptPrivateKey(encryptedPrivateKey: Uint8Array): Promise<Uint8Array>
  encryptMessage(text: string, publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array, encryptedSessionKey: Uint8Array }>
  decryptMessage(ciphertext: Uint8Array, encryptedSessionKey: Uint8Array): Promise<string>
  destroy(): void  // zero out cached keys
}

createSession(password: string, salt: Uint8Array, iv: Uint8Array)
  → Promise<Session>
```

**Files to modify:** new `src/session.ts`, update `src/index.ts` exports, add `test/session.test.ts`

---

## Tier 3 — Advanced

### 7. Signing and verification

Prove who sent a message. Without this, anyone with a recipient's public key can send them a message that looks legitimate. Needs a post-quantum signature scheme (Dilithium / FIPS 204).

```ts
generateSigningKeyPair() → { signingKey: Uint8Array, verifyKey: Uint8Array }
sign(data: Uint8Array, signingKey: Uint8Array) → Uint8Array
verify(data: Uint8Array, signature: Uint8Array, verifyKey: Uint8Array) → boolean
```

**Requires:** adding a Dilithium WASM module (similar to existing Kyber and Argon2 bundling)

**Files to modify:** new `src/signing.ts`, new WASM wrapper, update `src/index.ts` exports, add `test/signing.test.ts`

---

### 8. Key exchange helpers

Two users starting a conversation need to establish a shared secret. Kyber KEM is the primitive, but a higher-level API simplifies the handshake.

```ts
initiateKeyExchange(theirPublicKey: Uint8Array)
  → { sharedSecret: Uint8Array, exchangeData: Uint8Array }

completeKeyExchange(exchangeData: Uint8Array, myPrivateKey: Uint8Array)
  → Uint8Array  // sharedSecret
```

**Files to modify:** new `src/keyExchange.ts`, update `src/index.ts` exports, add `test/keyExchange.test.ts`

---

### 9. Password / key rotation

Users change passwords, keys get compromised, periodic rotation is needed. Single function to re-encrypt a private key under a new password without exposing the plaintext key to app code.

```ts
rotatePassword(
  encryptedPrivateKey: Uint8Array,
  oldPassword: string,
  oldSalt: Uint8Array,
  oldIv: Uint8Array,
  newPassword: string
) → { encryptedPrivateKey: Uint8Array, salt: Uint8Array, iv: Uint8Array }
```

**Files to modify:** extend `src/encryption.ts` or new `src/rotation.ts`, update `src/index.ts` exports, add tests

---

## Existing cleanup

These should be addressed alongside or before the new features:

- [ ] Remove debug `console.log` statements in `src/decryption.ts` (lines 114-115, 140, 187, 210, 219)
- [ ] Fix double private key decryption in `src/decryption.ts` (lines 145-151 decrypt then discard, line 151 decrypts again)
- [ ] Remove or formally deprecate legacy `encryptWithKyber`/`decryptWithKyber` in `src/kyber.ts`
