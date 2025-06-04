/**
 * Converts a Base64 URL-safe encoded string to standard Base64 encoding.
 *
 * Replaces URL-safe characters with standard Base64 equivalents and adds padding as needed.
 *
 * @param {string} input - The Base64 URL-safe encoded string.
 * @returns {string} The standard Base64 encoded string.
 */
export function b64urlToB64(input) {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) {
    b64 += "=";
  }
  return b64;
}

/**
 * Asynchronously generates an X25519 key pair and returns the public and private keys as Base64-encoded strings.
 *
 * The keys are exported in JWK format and the key material is converted from Base64 URL-safe encoding to standard Base64.
 *
 * @returns {Promise<{publicKey: string, privateKey: string}>} An object containing the Base64-encoded public and private keys.
 */
export async function generateKeypair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "X25519", namedCurve: "X25519" },
    true,
    ["deriveBits"],
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  return {
    publicKey: b64urlToB64(pubJwk.x),
    privateKey: b64urlToB64(privJwk.d),
  };
}

/**
 * Generates a cryptographically secure 32-byte preshared key.
 *
 * @returns {Uint8Array} A 32-byte array containing random key material suitable for use as a preshared key.
 */
export function generatePresharedKey() {
  let privateKey = new Uint8Array(32);
  window.crypto.getRandomValues(privateKey);
  return privateKey;
}

/**
 * Converts an ArrayBuffer or TypedArray to a Base64-encoded string.
 *
 * @param {ArrayBuffer|TypedArray} buffer - The binary data to encode.
 * @returns {string} The Base64-encoded representation of the input buffer.
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; ++i) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
