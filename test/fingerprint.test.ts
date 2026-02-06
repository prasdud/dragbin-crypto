import { describe, it, expect } from 'vitest';
import { generateKeyPair, createFingerprint, compareFingerprints } from '../src/index.js';

describe('Key Fingerprinting', () => {
  it('should create a fingerprint from a public key', async () => {
    const { publicKey } = await generateKeyPair();

    const fingerprint = await createFingerprint(publicKey);

    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBeGreaterThan(0);
  });

  it('should return uppercase hex with spaces', async () => {
    const { publicKey } = await generateKeyPair();

    const fingerprint = await createFingerprint(publicKey);

    // Should only contain uppercase hex chars and spaces
    expect(fingerprint).toMatch(/^[A-F0-9 ]+$/);
    // Should have spaces separating groups
    expect(fingerprint).toContain(' ');
  });

  it('should produce consistent fingerprint for the same key', async () => {
    const { publicKey } = await generateKeyPair();

    const fingerprint1 = await createFingerprint(publicKey);
    const fingerprint2 = await createFingerprint(publicKey);

    expect(fingerprint1).toBe(fingerprint2);
  });

  it('should produce different fingerprints for different keys', async () => {
    const { publicKey: key1 } = await generateKeyPair();
    const { publicKey: key2 } = await generateKeyPair();

    const fingerprint1 = await createFingerprint(key1);
    const fingerprint2 = await createFingerprint(key2);

    expect(fingerprint1).not.toBe(fingerprint2);
  });

  it('should work with private keys too', async () => {
    const { privateKey } = await generateKeyPair();

    const fingerprint = await createFingerprint(privateKey);

    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBeGreaterThan(0);
  });

  it('should produce a SHA-256 length fingerprint (64 hex chars + spaces)', async () => {
    const { publicKey } = await generateKeyPair();

    const fingerprint = await createFingerprint(publicKey);
    const hexOnly = fingerprint.replace(/ /g, '');

    // SHA-256 = 32 bytes = 64 hex chars
    expect(hexOnly.length).toBe(64);
  });
});

describe('Compare Fingerprints', () => {
  it('should return true for the same key', async () => {
    const { publicKey } = await generateKeyPair();

    const result = await compareFingerprints(publicKey, publicKey);

    expect(result).toBe(true);
  });

  it('should return true for identical key copies', async () => {
    const { publicKey } = await generateKeyPair();
    const copy = new Uint8Array(publicKey);

    const result = await compareFingerprints(publicKey, copy);

    expect(result).toBe(true);
  });

  it('should return false for different keys', async () => {
    const { publicKey: key1 } = await generateKeyPair();
    const { publicKey: key2 } = await generateKeyPair();

    const result = await compareFingerprints(key1, key2);

    expect(result).toBe(false);
  });

  it('should detect a single byte difference', async () => {
    const { publicKey } = await generateKeyPair();
    const tampered = new Uint8Array(publicKey);
    tampered[0] ^= 0x01;

    const result = await compareFingerprints(publicKey, tampered);

    expect(result).toBe(false);
  });
});
