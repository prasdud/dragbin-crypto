import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/index.js';
import { encryptForGroup, decryptFromGroup } from '../src/group.js';

describe('Group Encryption', () => {
  it('should encrypt a message for multiple recipients', async () => {
    const { publicKey: pub1 } = await generateKeyPair();
    const { publicKey: pub2 } = await generateKeyPair();
    const message = 'Hello group!';

    const encrypted = await encryptForGroup(message, [pub1, pub2]);

    expect(encrypted.encryptedData).toBeInstanceOf(Uint8Array);
    expect(encrypted.encryptedData.length).toBeGreaterThan(message.length);
    expect(encrypted.wrappedKeys).toHaveLength(2);
  });

  it('should produce different wrapped keys per recipient', async () => {
    const { publicKey: pub1 } = await generateKeyPair();
    const { publicKey: pub2 } = await generateKeyPair();
    const message = 'Same message, different keys';

    const encrypted = await encryptForGroup(message, [pub1, pub2]);

    expect(encrypted.wrappedKeys[0].kyberCipherText).not.toEqual(encrypted.wrappedKeys[1].kyberCipherText);
    expect(encrypted.wrappedKeys[0].wrappedSessionKey).not.toEqual(encrypted.wrappedKeys[1].wrappedSessionKey);
  });

  it('should produce different ciphertext each time', async () => {
    const { publicKey } = await generateKeyPair();
    const message = 'Same message twice';

    const result1 = await encryptForGroup(message, [publicKey]);
    const result2 = await encryptForGroup(message, [publicKey]);

    expect(result1.encryptedData).not.toEqual(result2.encryptedData);
  });

  it('should not contain the original message in plaintext', async () => {
    const { publicKey } = await generateKeyPair();
    const message = 'This should not appear in ciphertext';

    const encrypted = await encryptForGroup(message, [publicKey]);
    const encryptedString = new TextDecoder().decode(encrypted.encryptedData);

    expect(encryptedString).not.toContain(message);
  });
});

describe('Group Decryption', () => {
  it('should decrypt for the first recipient', async () => {
    const { publicKey: pub1, privateKey: priv1 } = await generateKeyPair();
    const { publicKey: pub2 } = await generateKeyPair();
    const message = 'Hello group!';

    const encrypted = await encryptForGroup(message, [pub1, pub2]);
    const decrypted = await decryptFromGroup(encrypted, priv1, 0);

    expect(decrypted).toBe(message);
  });

  it('should decrypt for the second recipient', async () => {
    const { publicKey: pub1 } = await generateKeyPair();
    const { publicKey: pub2, privateKey: priv2 } = await generateKeyPair();
    const message = 'Hello group!';

    const encrypted = await encryptForGroup(message, [pub1, pub2]);
    const decrypted = await decryptFromGroup(encrypted, priv2, 1);

    expect(decrypted).toBe(message);
  });

  it('should decrypt for all recipients and produce the same message', async () => {
    const pair1 = await generateKeyPair();
    const pair2 = await generateKeyPair();
    const pair3 = await generateKeyPair();
    const message = 'Everyone should read this';

    const encrypted = await encryptForGroup(message, [pair1.publicKey, pair2.publicKey, pair3.publicKey]);

    const decrypted1 = await decryptFromGroup(encrypted, pair1.privateKey, 0);
    const decrypted2 = await decryptFromGroup(encrypted, pair2.privateKey, 1);
    const decrypted3 = await decryptFromGroup(encrypted, pair3.privateKey, 2);

    expect(decrypted1).toBe(message);
    expect(decrypted2).toBe(message);
    expect(decrypted3).toBe(message);
  });

  it('should handle a single recipient', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'Just for one';

    const encrypted = await encryptForGroup(message, [publicKey]);
    const decrypted = await decryptFromGroup(encrypted, privateKey, 0);

    expect(decrypted).toBe(message);
  });

  it('should handle an empty message', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = '';

    const encrypted = await encryptForGroup(message, [publicKey]);
    const decrypted = await decryptFromGroup(encrypted, privateKey, 0);

    expect(decrypted).toBe(message);
  });

  it('should handle unicode and emoji', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'こんにちは 🔐 مرحبا 你好 🚀';

    const encrypted = await encryptForGroup(message, [publicKey]);
    const decrypted = await decryptFromGroup(encrypted, privateKey, 0);

    expect(decrypted).toBe(message);
  });

  it('should handle a long message', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'A'.repeat(10000);

    const encrypted = await encryptForGroup(message, [publicKey]);
    const decrypted = await decryptFromGroup(encrypted, privateKey, 0);

    expect(decrypted).toBe(message);
  });

  it('should fail to decrypt with wrong private key', async () => {
    const { publicKey: pub1 } = await generateKeyPair();
    const { privateKey: wrongPriv } = await generateKeyPair();
    const message = 'Secret message';

    const encrypted = await encryptForGroup(message, [pub1]);

    await expect(
      decryptFromGroup(encrypted, wrongPriv, 0),
    ).rejects.toThrow();
  });

  it('should fail to decrypt with wrong recipient index', async () => {
    const { publicKey: pub1, privateKey: priv1 } = await generateKeyPair();
    const { publicKey: pub2 } = await generateKeyPair();
    const message = 'Secret message';

    const encrypted = await encryptForGroup(message, [pub1, pub2]);

    // priv1 corresponds to index 0, not index 1
    await expect(
      decryptFromGroup(encrypted, priv1, 1),
    ).rejects.toThrow();
  });

  it('should fail to decrypt with tampered ciphertext', async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const message = 'Do not tamper';

    const encrypted = await encryptForGroup(message, [publicKey]);

    const tampered = new Uint8Array(encrypted.encryptedData);
    tampered[15] ^= 0xff;

    await expect(
      decryptFromGroup({ encryptedData: tampered, wrappedKeys: encrypted.wrappedKeys }, privateKey, 0),
    ).rejects.toThrow();
  });
});
