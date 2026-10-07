/**
 * Thin wrappers around the browser WebAuthn API (`navigator.credentials`)
 * that talk JSON with the GENOME Security server's `/api/register/*` and
 * `/api/login/*` endpoints (which use webauthn-rs's standard JSON
 * encoding of `PublicKeyCredentialCreationOptions` /
 * `PublicKeyCredentialRequestOptions`).
 *
 * Deliberately requests `userVerification: "required"` and does not force
 * a resident/discoverable key, matching the server's non-attested
 * "passkey" flow (see server/src/auth.rs doc comments for the honest
 * trade-off versus a fully attested, hardware-catalog-verified flow).
 */

import { base64urlToBuffer, bufferToBase64url } from "./base64url";

function b64uFieldsToBuffers(options: any): any {
  const out = structuredCloneOptions(options);
  if (out.challenge) out.challenge = base64urlToBuffer(out.challenge);
  if (out.user?.id) out.user.id = base64urlToBuffer(out.user.id);
  for (const list of [out.excludeCredentials, out.allowCredentials]) {
    if (Array.isArray(list)) {
      for (const cred of list) {
        if (cred.id) cred.id = base64urlToBuffer(cred.id);
      }
    }
  }
  return out;
}

function structuredCloneOptions(options: any): any {
  return JSON.parse(JSON.stringify(options));
}

function credentialToJSON(cred: PublicKeyCredential): any {
  const response = cred.response;
  const base = {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
  };

  if (response instanceof AuthenticatorAttestationResponse) {
    return {
      ...base,
      response: {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        attestationObject: bufferToBase64url(response.attestationObject),
      },
    };
  }

  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...base,
    response: {
      clientDataJSON: bufferToBase64url(assertion.clientDataJSON),
      authenticatorData: bufferToBase64url(assertion.authenticatorData),
      signature: bufferToBase64url(assertion.signature),
      userHandle: assertion.userHandle ? bufferToBase64url(assertion.userHandle) : null,
    },
  };
}

/** Run `navigator.credentials.create()` against server-supplied options. */
export async function createCredential(
  publicKeyOptions: unknown,
): Promise<{ credentialJSON: unknown }> {
  const publicKey = b64uFieldsToBuffers(publicKeyOptions);
  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("WebAuthn registration was cancelled or returned no credential");
  return { credentialJSON: credentialToJSON(credential) };
}

/** Run `navigator.credentials.get()` against server-supplied options. */
export async function getCredential(
  publicKeyOptions: unknown,
): Promise<{ credentialJSON: unknown }> {
  const publicKey = b64uFieldsToBuffers(publicKeyOptions);
  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("WebAuthn assertion was cancelled or returned no credential");
  return { credentialJSON: credentialToJSON(credential) };
}

/**
 * Best-effort check for whether this platform/browser combination can
 * provide a device-bound (non-syncable) authenticator. Not all browsers
 * expose this distinction yet; callers should treat `null` as "unknown"
 * rather than "no".
 */
export async function supportsDeviceBoundAuthenticator(): Promise<boolean | null> {
  const pkc = (window as any).PublicKeyCredential;
  if (!pkc?.isConditionalMediationAvailable && !pkc?.isUserVerifyingPlatformAuthenticatorAvailable) {
    return null;
  }
  try {
    return await pkc.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return null;
  }
}
