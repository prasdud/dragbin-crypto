/**
 * Symmetric messaging encryption and decryption example for @dragbin/crypto
 *
 * Demonstration of message encryption and decryption using password-derived keys with Argon2id
 * and AES-GCM for message encryption.
 */

import { encryptSymmetricMessage, decryptSymmetricMessage } from "../src/index.ts";

async function main() {

    const message = 'I hate typescript!';
    const password = 'ultrasecure69';

    console.log('Original message:', message);
    
    const encryptedMessage = await encryptSymmetricMessage(message, password);
    console.log('Encrypted message:', encryptedMessage);

    const decryptedMessage = await decryptSymmetricMessage(encryptedMessage, password);
    console.log('Decrypted message:', decryptedMessage);

    if (decryptedMessage === message) {
        console.log('✅ Decryption successful, messages match!');
    } else {
        console.error('❌ Decryption failed, messages do not match!');
    }
}

main().catch(console.error);