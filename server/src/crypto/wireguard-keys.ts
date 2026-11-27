import { generateKeyPairSync } from 'node:crypto';

/**
 * Generate an X25519 key pair and return the 32-byte raw keys as Base64.
 * This primitive is not yet validated for WireGuard interoperability.
 * Verify key clamping and output against the target WireGuard implementation.
 */
export function generateX25519KeyPair(): { privateKey: string; publicKey: string } {
  const pair = generateKeyPairSync('x25519');
  const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' });
  const privateRaw = privateDer.subarray(-32);
  const publicRaw = publicDer.subarray(-32);
  if (privateRaw.length !== 32 || publicRaw.length !== 32) {
    throw new Error('Unexpected X25519 key encoding');
  }
  return {
    privateKey: privateRaw.toString('base64'),
    publicKey: publicRaw.toString('base64')
  };
}
