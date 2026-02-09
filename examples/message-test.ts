/**
 * Messaging encryption and decryption example for @dragbin/crypto
 *
 * Demonstration of message encryption and decryption using Kyber KEM for session key generation
 * and AES-GCM for message encryption.
 */

import { generateKeyPair, encryptMessage, decryptMessage } from '../src/index.js';

async function main() {
  // 1. Generate Kyber key pair
  const { publicKey, privateKey } = await generateKeyPair();

  // 2. Encrypt a message
  const message = 'Hello, this is a secret message!';
  const encryptedMessage = await encryptMessage(message, publicKey);
  console.log('Encrypted Message:', encryptedMessage);

  // 3. Decrypt the message
  const decryptedMessage = await decryptMessage(encryptedMessage, privateKey);
  console.log('Decrypted Message:', decryptedMessage);

  if (message === decryptedMessage) {
    console.log('Success: Decrypted message matches original');
  } else {
    console.error('Error: Decrypted message does NOT match original');
  }
}

main().catch(console.error);

