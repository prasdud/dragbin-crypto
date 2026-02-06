/**
 * @dragbin/crypto
 *
 * Zero-dependency encryption library using Kyber post-quantum cryptography
 * and Argon2id password hashing.
 *
 * Features:
 * - Post-quantum secure encryption (Kyber1024)
 * - Memory-hard password hashing (Argon2id)
 * - File encryption with chunked AES-GCM
 * - Password-protected private keys
 * - Compatible with Dragbin file storage system
 *
 * @example Basic usage
 * ```typescript
 * import { generateKeyPair, encryptFile, decryptFile, encryptPrivateKey } from '@dragbin/crypto';
 *
 * // 1. Generate key pair
 * const { publicKey, privateKey } = await generateKeyPair();
 *
 * // 2. Encrypt private key with password
 * const password = 'mySecurePassword123';
 * const { encryptedPrivateKey, salt, iv } = await encryptPrivateKey(privateKey, password);
 *
 * // 3. Encrypt a file
 * const fileData = new Uint8Array([...]); // Your file
 * const { encryptedData } = await encryptFile(fileData, publicKey);
 *
 * // 4. Later, decrypt the file
 * const decryptedFile = await decryptFile(
 *   encryptedData,
 *   password,
 *   encryptedPrivateKey,
 *   salt,
 *   iv
 * );
 * ```
 *
 * @packageDocumentation
 */

// Export types
export type { KyberKeyPair, EncryptedFile, DerivedKey, EncryptedPrivateKey, EncryptedMessage, SymmetricEncryptedMessage } from './types.js';

// Export key generation
export { generateKyberKeyPair as generateKeyPair } from './kyber.js';

// Export file encryption/decryption
export { encryptFile } from './encryption.js';
export { decryptFile } from './decryption.js';

// Export private key encryption/decryption
export { encryptPrivateKey } from './encryption.js';
export { decryptPrivateKey } from './decryption.js';

// Export key derivation
export { deriveKeyFromPassword } from './keyDerivation.js';

// Export utility functions
export { generateSalt } from './utils.js';

// Export message encryption/decryption
export { encryptMessage, decryptMessage } from './message.js';

// Export symmetric message encryption/decryption
export { encryptSymmetricMessage, decryptSymmetricMessage } from './symmetric-message.js';

// Export serialization utilities
export { exportBytes, importBytes, exportKeyPair, importKeyPair } from './serialization.js';
