/**
 * Group encryption using hybrid Kyber KEM + AES-GCM
 *
 * Encrypts a message once, wraps the session key per-recipient using Kyber.
 * Each recipient can independently decrypt using their own private key.
 */

import { generateIV, concatUint8Arrays } from "./utils.js";
import type { GroupEncryptedMessage } from "./types.js";
import { kyberEncapsulate, kyberDecapsulate } from "./kyber.js";

/**
 * Encrypt a message for multiple recipients
 *
 * Process:
 * 1. Generate a random AES-GCM-256 session key
 * 2. Encrypt the message once with the session key
 * 3. For each recipient: Kyber KEM → shared secret → wrap session key
 *
 * @param message - Plaintext message to encrypt
 * @param publicKeys - Array of recipient Kyber public keys (1568 bytes each)
 * @returns Encrypted message + per-recipient wrapped session keys
 */
export async function encryptForGroup(
    message: string,
    publicKeys: Uint8Array[],
): Promise<GroupEncryptedMessage>{

    // Generate a random session key — this encrypts the actual message
    const sessionKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        [ 'encrypt', 'decrypt' ],
    );

    const iv = generateIV();

    // Export session key to raw bytes so we can wrap it for each recipient
    const rawSessionKey = await crypto.subtle.exportKey('raw', sessionKey)

    // Encrypt the message once with the session key
    const encryptedMessage = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv as any,
        },
        sessionKey,
        new TextEncoder().encode(message),
    );

    // Wrap the session key for each recipient using Kyber KEM
    const wrappedKeys = [];

    for (const key of publicKeys) {
        // Kyber encapsulate: generates a shared secret + ciphertext per recipient
        const { ciphertext: kyberEncryptedSessionKey, secret: sharedSecret } = await kyberEncapsulate(key)

        // Import the shared secret as an AES wrapping key
        const wrappingKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(sharedSecret),
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        // Encrypt the raw session key with the wrapping key
        const wrappedIv = generateIV();
        const encryptedSessionKey = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv : wrappedIv as any,
            },
            wrappingKey,
            rawSessionKey
        );

        // Store Kyber ciphertext + wrapped session key (IV prepended)
        wrappedKeys.push({
            kyberCipherText: kyberEncryptedSessionKey,
            wrappedSessionKey: concatUint8Arrays(wrappedIv, new Uint8Array(encryptedSessionKey))
        });
    }

    // encryptedData format: [IV (12 bytes)][AES-GCM ciphertext]
    // wrappedSessionKey format per recipient: [IV (12 bytes)][AES-GCM encrypted session key]
    return {
        encryptedData: concatUint8Arrays(iv, new Uint8Array(encryptedMessage)),
        wrappedKeys: wrappedKeys,
    };
}

/**
 * Decrypt a group-encrypted message as a specific recipient
 *
 * Process (two layers):
 * Layer 1 — Unwrap the session key:
 *   1. Get this recipient's wrapped key by index
 *   2. Kyber decapsulate → recover shared secret
 *   3. Use shared secret to decrypt the wrapped session key
 *
 * Layer 2 — Decrypt the message:
 *   4. Use the recovered session key to decrypt the message
 *
 * @param encrypted - The full group-encrypted payload
 * @param privateKey - This recipient's Kyber private key (3168 bytes)
 * @param recipientIndex - This recipient's position in the wrappedKeys array
 * @returns Decrypted message string
 */
export async function decryptFromGroup(
    encrypted: GroupEncryptedMessage,
    privateKey: Uint8Array,
    recipientIndex: number,
): Promise<string> {

    // --- Layer 1: Unwrap the session key ---

    // Get this recipient's wrapped key entry
    const myWrappedKey = encrypted.wrappedKeys[recipientIndex];

    // Kyber decapsulate: recover the shared secret using our private key
    const sharedSecret = await kyberDecapsulate(myWrappedKey.kyberCipherText, privateKey);

    // Import the shared secret as an AES unwrapping key
    const wrappingKey = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(sharedSecret),
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
    );

    // Split the wrapped session key: [IV (12 bytes)][encrypted session key]
    const wrappingIv = myWrappedKey.wrappedSessionKey.subarray(0, 12);
    const encryptedSessionKey = myWrappedKey.wrappedSessionKey.subarray(12);

    // Decrypt to recover the raw session key
    const rawSessionKey = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: wrappingIv as any,
        },
        wrappingKey,
        encryptedSessionKey as any,
    );

    // --- Layer 2: Decrypt the message ---

    // Import the recovered session key for message decryption
    const sessionKey = await crypto.subtle.importKey(
        'raw',
        rawSessionKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
    );

    // Split the encrypted data: [IV (12 bytes)][ciphertext]
    const iv = encrypted.encryptedData.subarray(0, 12);
    const ciphertext = encrypted.encryptedData.subarray(12);

    // Decrypt the message
    const decryptedMessageBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv as any,
        },
        sessionKey,
        ciphertext as any,
    );

    return new TextDecoder().decode(decryptedMessageBuffer);
}
