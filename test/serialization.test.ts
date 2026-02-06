import { describe, it, expect } from 'vitest';
import { generateKeyPair, exportBytes, importBytes, exportKeyPair, importKeyPair } from '../src/index.js';

describe('Byte Serialization', () => {
  it('should round-trip a Uint8Array through base64', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5]);

    const exported = exportBytes(original);
    const imported = importBytes(exported);

    expect(imported).toEqual(original);
  });

  it('should return a string from exportBytes', () => {
    const data = new Uint8Array([10, 20, 30]);

    const exported = exportBytes(data);

    expect(typeof exported).toBe('string');
    expect(exported.length).toBeGreaterThan(0);
  });

  it('should handle an empty Uint8Array', () => {
    const original = new Uint8Array(0);

    const exported = exportBytes(original);
    const imported = importBytes(exported);

    expect(imported).toEqual(original);
  });

  it('should handle large data', () => {
    const original = new Uint8Array(10000);
    crypto.getRandomValues(original);

    const exported = exportBytes(original);
    const imported = importBytes(exported);

    expect(imported).toEqual(original);
  });

  it('should produce valid base64', () => {
    const data = new Uint8Array([255, 128, 0, 64, 32]);

    const exported = exportBytes(data);

    // Valid base64 only contains these characters
    expect(exported).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  it('should produce different base64 for different data', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);

    expect(exportBytes(a)).not.toBe(exportBytes(b));
  });
});

describe('Key Pair Serialization', () => {
  it('should round-trip a key pair through base64', async () => {
    const original = await generateKeyPair();

    const exported = exportKeyPair(original);
    const imported = importKeyPair(exported);

    expect(imported.publicKey).toEqual(original.publicKey);
    expect(imported.privateKey).toEqual(original.privateKey);
  });

  it('should return strings from exportKeyPair', async () => {
    const keyPair = await generateKeyPair();

    const exported = exportKeyPair(keyPair);

    expect(typeof exported.publicKey).toBe('string');
    expect(typeof exported.privateKey).toBe('string');
    expect(exported.publicKey.length).toBeGreaterThan(0);
    expect(exported.privateKey.length).toBeGreaterThan(0);
  });

  it('should produce different strings for public and private keys', async () => {
    const keyPair = await generateKeyPair();

    const exported = exportKeyPair(keyPair);

    expect(exported.publicKey).not.toBe(exported.privateKey);
  });

  it('should produce different exports for different key pairs', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();

    const exported1 = exportKeyPair(keyPair1);
    const exported2 = exportKeyPair(keyPair2);

    expect(exported1.publicKey).not.toBe(exported2.publicKey);
    expect(exported1.privateKey).not.toBe(exported2.privateKey);
  });

  it('should preserve key sizes after round-trip', async () => {
    const original = await generateKeyPair();

    const exported = exportKeyPair(original);
    const imported = importKeyPair(exported);

    expect(imported.publicKey.length).toBe(1568);
    expect(imported.privateKey.length).toBe(3168);
  });
});
