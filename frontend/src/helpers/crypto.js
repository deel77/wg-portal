export function b64urlToB64(input) {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) {
    b64 += "=";
  }
  return b64;
}

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

export function generatePresharedKey() {
  let privateKey = new Uint8Array(32);
  window.crypto.getRandomValues(privateKey);
  return privateKey;
}

export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; ++i) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
