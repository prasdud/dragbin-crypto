/**
 * Symmetric message encryption using password-derived keys with Argon2id and AES-GCM
 */

import { deriveKeyFromPassword } from './keyDerivation.js';
import {
  generateIV,
  concatUint8Arrays,
} from './utils.js';
import type { SymmetricEncryptedMessage } from './types.js';

export async function encryptSymmetricMessage(
    message: string,
    password: string,
    salt?: Uint8Array,
): Promise<SymmetricEncryptedMessage> {

    // generate argon2id derived key from password and salt
    const derivedKey = await deriveKeyFromPassword(password, salt);

    // generate random IV for AES-GCM
    const iv = generateIV();

    // encrypt the message using AES-GCM with the derived key
    const encryptedMessage = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv as any, // TypeScript workaround for IV type
        },
        derivedKey.key,
        new TextEncoder().encode(message),
    );

    // Return the encrypted message along with the salt used for key derivation (if it was generated)
    return {
        encryptedData: concatUint8Arrays(iv, new Uint8Array(encryptedMessage)),
        salt: derivedKey.salt,
    };
}


export async function decryptSymmetricMessage(
    encryptedMessage: SymmetricEncryptedMessage,
    password: string,
): Promise<string> {
    const { encryptedData, salt } = encryptedMessage;

    // Derive the key from the password and salt
    const derivedKey = await deriveKeyFromPassword(password, salt);
    
    // Extract IV from the beginning of the encrypted data
    const iv = encryptedData.subarray(0, 12); // AES-GCM IV is 12 bytes
    const ciphertext = encryptedData.subarray(12);

    // Decrypt the message using AES-GCM with the derived key
    const decryptedMessageBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv as any, // TypeScript workaround for IV type
        },
        derivedKey.key,
        ciphertext as any, // TypeScript workaround for ciphertext type
    );
    
    // Return the decrypted message as a string
    return new TextDecoder().decode(decryptedMessageBuffer);
}