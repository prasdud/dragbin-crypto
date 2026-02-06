/**
 * Message encryption using Kyber KEM and AES-GCM
 */

import { kyberEncapsulate, kyberDecapsulate } from './kyber.js';
import {
  generateIV,
  concatUint8Arrays,
} from './utils.js';
import type { EncryptedMessage } from './types.js';

export async function encryptMessage(
    message: string,
    publicKey: Uint8Array,
): Promise<EncryptedMessage> {
    // Use Kyber KEM to generate session key and ciphertext
    const { ciphertext: kyberEncryptedSessionKey, secret: rawSessionKey } = await kyberEncapsulate(publicKey);

    // Import the Kyber-generated secret as AES-GCM session key
    const sessionKey = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(rawSessionKey),
        { name: 'AES-GCM' },
        false,
        ['encrypt'],
    );

    // Generate random IV for AES-GCM
    const iv = generateIV();

    // Encrypt the message using AES-GCM
    const encryptedMessage = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv as any, // TypeScript workaround for IV type
        },
        sessionKey,
        new TextEncoder().encode(message),
    );

    // Format: [IV (12 bytes)][Encrypted data]
    const encryptedData = concatUint8Arrays(iv, new Uint8Array(encryptedMessage));


    // Return the encrypted message along with the Kyber-encrypted session key
    return {
        encryptedData: encryptedData,
        kyberEncryptedSessionKey: kyberEncryptedSessionKey,
    };
}


export async function decryptMessage(
    encryptedMessage: EncryptedMessage,
    privateKey: Uint8Array,
): Promise<string> {
    const { encryptedData, kyberEncryptedSessionKey } = encryptedMessage;

    // Decrypt the session key using Kyber
    const rawSessionKey = await kyberDecapsulate(kyberEncryptedSessionKey, privateKey);

    // Import the Kyber-generated secret as AES-GCM session key
    const sessionKey = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(rawSessionKey),
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
    );

    // Extract IV and encrypted data
    const iv = encryptedData.subarray(0, 12);
    const ciphertext = encryptedData.subarray(12);
    
    // Decrypt the message using AES-GCM
    const decryptedMessageBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv as any, // TypeScript workaround for IV type
        },
        sessionKey,
        ciphertext as any, // TypeScript workaround for ciphertext type
    );

    return new TextDecoder().decode(decryptedMessageBuffer);
}