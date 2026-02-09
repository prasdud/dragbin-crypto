# Messaging & Social Media Roadmap

Features needed in `@dragbin/crypto` to support messaging and social media applications.

## Completed

### 1. Lightweight message encryption ✅

Compact Kyber KEM + single AES-GCM encrypt for chat messages. No chunking or metadata header overhead.

**Added:** `src/message.ts`, `test/message.test.ts`

---

### 2. Symmetric encrypt/decrypt (password-only mode) ✅

Password-based encryption for shared-secret chat rooms. Argon2id key derivation + AES-GCM. No Kyber involved.

**Added:** `src/symmetric-message.ts`, `test/symmetric-message.test.ts`

---

### 3. Key serialization ✅

Base64 serialization for keys and binary data. Enables storage in databases, HTTP transport, JWTs.

**Added:** `src/serialization.ts`, `test/serialization.test.ts`

---

### 4. Key fingerprinting ✅

SHA-256 hash of public keys, formatted as uppercase hex groups for human-readable verification.

**Added:** `createFingerprint` and `compareFingerprints` in `src/utils.ts`, `test/fingerprint.test.ts`

---

### 5. Multi-recipient encryption ✅

Group chats. Encrypt a message once with a random session key, Kyber-wrap the session key per recipient. Each recipient decrypts independently with their own private key.

**Added:** `src/group.ts`, `test/group.test.ts`

---

## Future Enhancements

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

