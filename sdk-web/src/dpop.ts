/**
 * RFC 9449 DPoP (Demonstrating Proof-of-Possession) support.
 *
 * Generates a non-extractable ES256 (P-256) WebCrypto keypair bound to the
 * browser session, computes its RFC 7638 JWK thumbprint (`jkt`), and signs
 * a fresh DPoP proof JWT for every outbound request per RFC 9449 section 4.
 */

import { bufferToBase64url } from "./base64url";

export interface DpopKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  /** RFC 7638 JWK thumbprint of the public key, base64url-encoded. */
  jkt: string;
}

function toJsonBase64url(obj: unknown): string {
  return bufferToBase64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function publicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  // RFC 7638 thumbprint requires exactly these members, lexicographically
  // ordered, with no extra whitespace -- we recompute a clean object here
  // rather than trusting key ordering from exportKey.
  return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } as JsonWebKey;
}

async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  // Canonical member order per RFC 7638 section 3.2: alphabetical.
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return bufferToBase64url(digest);
}

/** Generate a new non-extractable DPoP signing keypair for this session. */
export async function createDpopKeyPair(): Promise<DpopKeyPair> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true, // publicKey portion must be exportable so we can send the JWK
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const jwk = await publicJwk(keyPair.publicKey);
  const jkt = await jwkThumbprint(jwk);

  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, jkt };
}

export interface DpopProofOptions {
  /** HTTP method of the request this proof is bound to (e.g. "POST"). */
  htm: string;
  /** Full target URL of the request this proof is bound to. */
  htu: string;
  /** Access/session token to bind via the `ath` claim, if one is already held. */
  accessToken?: string;
}

/** Sign a fresh DPoP proof JWT for a single outbound HTTP request. */
export async function signDpopProof(keyPair: DpopKeyPair, opts: DpopProofOptions): Promise<string> {
  const jwk = await publicJwk(keyPair.publicKey);
  const header = { typ: "dpop+jwt", alg: "ES256", jwk };
  const payload: Record<string, unknown> = {
    htm: opts.htm.toUpperCase(),
    htu: opts.htu,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  };
  if (opts.accessToken) {
    const athDigest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(opts.accessToken),
    );
    payload.ath = bufferToBase64url(athDigest);
  }

  const signingInput = `${toJsonBase64url(header)}.${toJsonBase64url(payload)}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${bufferToBase64url(signature)}`;
}
