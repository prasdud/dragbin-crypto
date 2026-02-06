import { describe, it, expect } from 'vitest';
import { encryptSymmetricMessage, decryptSymmetricMessage } from '../src/index.js';

describe('Symmetric Message Encryption', () => {
  it('should encrypt a message', async () => {
    const password = 'testPassword123';
    const message = 'Hello, this is a secret message!';

    const { encryptedData, salt } = await encryptSymmetricMessage(message, password);

    expect(encryptedData).toBeInstanceOf(Uint8Array);
    expect(encryptedData.length).toBeGreaterThan(message.length);
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBe(16);
  });

  it('should produce different encrypted data for the same message and password', async () => {
    const password = 'testPassword123';
    const message = 'Same message twice';

    const result1 = await encryptSymmetricMessage(message, password);
    const result2 = await encryptSymmetricMessage(message, password);

    // Different due to random salt and IV
    expect(result1.encryptedData).not.toEqual(result2.encryptedData);
    expect(result1.salt).not.toEqual(result2.salt);
  });

  it('should produce same salt when salt is provided', async () => {
    const password = 'testPassword123';
    const message = 'Message with fixed salt';
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const result = await encryptSymmetricMessage(message, password, salt);

    expect(result.salt).toEqual(salt);
  });

  it('should not contain the original message in plaintext', async () => {
    const password = 'testPassword123';
    const message = 'This should not appear in ciphertext';

    const { encryptedData } = await encryptSymmetricMessage(message, password);
    const encryptedString = new TextDecoder().decode(encryptedData);

    expect(encryptedString).not.toContain(message);
  });
});

describe('Symmetric Message Decryption', () => {
  it('should decrypt a message with the correct password', async () => {
    const password = 'testPassword123';
    const message = 'Hello, this is a secret message!';

    const encrypted = await encryptSymmetricMessage(message, password);
    const decrypted = await decryptSymmetricMessage(encrypted, password);

    expect(decrypted).toBe(message);
  });

  it('should handle an empty message', async () => {
    const password = 'testPassword123';
    const message = '';

    const encrypted = await encryptSymmetricMessage(message, password);
    const decrypted = await decryptSymmetricMessage(encrypted, password);

    expect(decrypted).toBe(message);
  });

  it('should handle a long message', async () => {
    const password = 'testPassword123';
    const message = 'A'.repeat(10000);

    const encrypted = await encryptSymmetricMessage(message, password);
    const decrypted = await decryptSymmetricMessage(encrypted, password);

    expect(decrypted).toBe(message);
  });

  it('should handle unicode and emoji', async () => {
    const password = 'testPassword123';
    const message = 'こんにちは 🔐 مرحبا 你好 🚀';

    const encrypted = await encryptSymmetricMessage(message, password);
    const decrypted = await decryptSymmetricMessage(encrypted, password);

    expect(decrypted).toBe(message);
  });

  it('should handle special characters and newlines', async () => {
    const password = 'testPassword123';
    const message = 'Line 1\nLine 2\tTabbed\r\n"quotes" & <html> \'escaped\'';

    const encrypted = await encryptSymmetricMessage(message, password);
    const decrypted = await decryptSymmetricMessage(encrypted, password);

    expect(decrypted).toBe(message);
  });

  it('should decrypt with a provided salt', async () => {
    const password = 'testPassword123';
    const message = 'Message with fixed salt';
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const encrypted = await encryptSymmetricMessage(message, password, salt);
    const decrypted = await decryptSymmetricMessage(encrypted, password);

    expect(decrypted).toBe(message);
  });

  it('should fail to decrypt with wrong password', async () => {
    const password = 'correctPassword';
    const wrongPassword = 'wrongPassword';
    const message = 'Secret message';

    const encrypted = await encryptSymmetricMessage(message, password);

    await expect(
      decryptSymmetricMessage(encrypted, wrongPassword),
    ).rejects.toThrow();
  });

  it('should fail to decrypt with tampered ciphertext', async () => {
    const password = 'testPassword123';
    const message = 'Do not tamper with me';

    const encrypted = await encryptSymmetricMessage(message, password);

    // Flip a byte in the encrypted data (after the IV)
    const tampered = new Uint8Array(encrypted.encryptedData);
    tampered[15] ^= 0xff;

    await expect(
      decryptSymmetricMessage({ encryptedData: tampered, salt: encrypted.salt }, password),
    ).rejects.toThrow();
  });

  it('should fail to decrypt with tampered salt', async () => {
    const password = 'testPassword123';
    const message = 'Do not tamper with me';

    const encrypted = await encryptSymmetricMessage(message, password);
    const tamperedSalt = crypto.getRandomValues(new Uint8Array(16));

    await expect(
      decryptSymmetricMessage({ encryptedData: encrypted.encryptedData, salt: tamperedSalt }, password),
    ).rejects.toThrow();
  });

  it('should allow multiple people to decrypt with the same password', async () => {
    const sharedPassword = 'room-password-42';
    const message = 'Hello everyone in the room!';

    // Alice encrypts
    const encrypted = await encryptSymmetricMessage(message, sharedPassword);

    // Bob decrypts with the same password
    const bobDecrypted = await decryptSymmetricMessage(encrypted, sharedPassword);

    // Charlie decrypts with the same password
    const charlieDecrypted = await decryptSymmetricMessage(encrypted, sharedPassword);

    expect(bobDecrypted).toBe(message);
    expect(charlieDecrypted).toBe(message);
  });
});
