import { describe, it, expect } from 'vitest';
import { generateKeyPair, encryptMessage, decryptMessage } from '../src/index.js';

describe('Message Encryption', () => {
  it('should encrypt a message', async () => {
    const { publicKey } = await generateKeyPair();
    const message = 'Hello, this is a secret message!';

    const { encryptedData, kyberEncryptedSessionKey } = await encryptMessage(message, publicKey);

    // Encrypted data should exist and be larger than raw message (IV + auth tag overhead)
    expect(encryptedData).toBeInstanceOf(Uint8Array);
    expect(encryptedData.length).toBeGreaterThan(message.length);

    // First 12 bytes should be the IV
    expect(encryptedData.length).toBeGreaterThanOrEqual(12);

    // Kyber encrypted session key should exist
    expect(kyberEncryptedSessionKey).toBeInstanceOf(Uint8Array);
    expect(kyberEncryptedSessionKey.length).toBeGreaterThan(0);
  });

  it('should produce different encrypted data for the same message', async () => {
    const { publicKey } = await generateKeyPair();
    const message = 'Same message twice';

    const result1 = await encryptMessage(message, publicKey);
    const result2 = await encryptMessage(message, publicKey);

    // Should be different due to random IVs and session keys
    expect(result1.encryptedData).not.toEqual(result2.encryptedData);
    expect(result1.kyberEncryptedSessionKey).not.toEqual(result2.kyberEncryptedSessionKey);
  });

  it('should not contain the original message in plaintext', async () => {
    const { publicKey } = await generateKeyPair();
    const message = 'This should not appear in ciphertext';

    const { encryptedData } = await encryptMessage(message, publicKey);
    const encryptedString = new TextDecoder().decode(encryptedData);

    expect(encryptedString).not.toContain(message);
  });
});

describe('Message Decryption', () => {
  it('should decrypt a message with the correct key pair', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'Hello, this is a secret message!';

    const encrypted = await encryptMessage(message, publicKey);
    const decrypted = await decryptMessage(encrypted, privateKey);

    expect(decrypted).toBe(message);
  });

  it('should handle an empty message', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = '';

    const encrypted = await encryptMessage(message, publicKey);
    const decrypted = await decryptMessage(encrypted, privateKey);

    expect(decrypted).toBe(message);
  });

  it('should handle a long message', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'A'.repeat(10000);

    const encrypted = await encryptMessage(message, publicKey);
    const decrypted = await decryptMessage(encrypted, privateKey);

    expect(decrypted).toBe(message);
  });

  it('should handle unicode and emoji', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'こんにちは 🔐 مرحبا 你好 🚀';

    const encrypted = await encryptMessage(message, publicKey);
    const decrypted = await decryptMessage(encrypted, privateKey);

    expect(decrypted).toBe(message);
  });

  it('should handle special characters and newlines', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'Line 1\nLine 2\tTabbed\r\n"quotes" & <html> \'escaped\'';

    const encrypted = await encryptMessage(message, publicKey);
    const decrypted = await decryptMessage(encrypted, privateKey);

    expect(decrypted).toBe(message);
  });

  it('should fail to decrypt with wrong private key', async () => {
    const { publicKey: pub1 } = await generateKeyPair();
    const { privateKey: priv2 } = await generateKeyPair();
    const message = 'Secret message';

    const encrypted = await encryptMessage(message, pub1);

    await expect(
      decryptMessage(encrypted, priv2),
    ).rejects.toThrow();
  });

  it('should fail to decrypt with tampered ciphertext', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'Do not tamper with me';

    const encrypted = await encryptMessage(message, publicKey);

    // Flip a byte in the encrypted data (after the IV)
    const tampered = new Uint8Array(encrypted.encryptedData);
    tampered[15] ^= 0xff;

    await expect(
      decryptMessage({ encryptedData: tampered, kyberEncryptedSessionKey: encrypted.kyberEncryptedSessionKey }, privateKey),
    ).rejects.toThrow();
  });

  it('should fail to decrypt with tampered session key', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'Do not tamper with me';

    const encrypted = await encryptMessage(message, publicKey);

    // Flip a byte in the session key
    const tamperedKey = new Uint8Array(encrypted.kyberEncryptedSessionKey);
    tamperedKey[0] ^= 0xff;

    await expect(
      decryptMessage({ encryptedData: encrypted.encryptedData, kyberEncryptedSessionKey: tamperedKey }, privateKey),
    ).rejects.toThrow();
  });
});
