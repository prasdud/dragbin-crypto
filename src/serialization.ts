/**
 * Key and message serialization utilities for @dragbin/crypto
 */

import {base64ToBytes, bytesToBase64} from './utils.js';
import type { KyberKeyPair } from './types.js';

// exports any Uint8Array to base64 string for storage and transmission
export function exportBytes(data: Uint8Array): string {
  return bytesToBase64(data);
}

// imports base64 string back to Uint8Array
export function importBytes(base64: string): Uint8Array {
  return base64ToBytes(base64);
}

// export key pair as base64 strings
export function exportKeyPair(keyPair: KyberKeyPair): { publicKey: string, privateKey: string } {
  return {
    publicKey: exportBytes(keyPair.publicKey),
    privateKey: exportBytes(keyPair.privateKey),
  };
}

// import key pair from base64 strings back to Uint8Arrays
export function importKeyPair(encoded: { publicKey: string, privateKey: string }): KyberKeyPair {
  return {
    publicKey: importBytes(encoded.publicKey),
    privateKey: importBytes(encoded.privateKey),
  };
}