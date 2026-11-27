import { deflateSync } from 'node:zlib';

/**
 * Provisional Amnezia-style vpn:// encoder.
 * The serialization must be verified against official Amnezia client fixtures
 * before it is used to distribute real configurations.
 */
export function encodeVpnUri(payload: string | Buffer): string {
  const input = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(input.length, 0);
  const compressed = deflateSync(input);
  return `vpn://${Buffer.concat([length, compressed]).toString('base64url')}`;
}
