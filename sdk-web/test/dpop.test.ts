import { describe, expect, it } from "vitest";
import { base64urlToBuffer, bufferToBase64url } from "../src/base64url";
import { createDpopKeyPair, signDpopProof } from "../src/dpop";

describe("base64url helpers", () => {
  it("round-trips arbitrary byte sequences", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255, 16, 32, 64, 128]);
    const encoded = bufferToBase64url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    const decoded = new Uint8Array(base64urlToBuffer(encoded));
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });
});

describe("DPoP proof generation", () => {
  it("produces a well-formed 3-part JWT with the expected claims", async () => {
    const keyPair = await createDpopKeyPair();
    expect(keyPair.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/); // base64url SHA-256, 32 bytes

    const proof = await signDpopProof(keyPair, {
      htm: "post",
      htu: "http://localhost:8080/api/login/finish",
    });
    const parts = proof.split(".");
    expect(parts).toHaveLength(3);

    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk.kty).toBe("EC");

    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("http://localhost:8080/api/login/finish");
    expect(typeof payload.jti).toBe("string");
    expect(typeof payload.iat).toBe("number");
    expect(payload.ath).toBeUndefined();
  });

  it("includes an `ath` claim bound to the access token when provided", async () => {
    const keyPair = await createDpopKeyPair();
    const proof = await signDpopProof(keyPair, {
      htm: "POST",
      htu: "http://localhost:8080/api/telemetry",
      accessToken: "session-token-123",
    });
    const payload = JSON.parse(Buffer.from(proof.split(".")[1], "base64url").toString("utf8"));
    expect(typeof payload.ath).toBe("string");
    expect(payload.ath).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("produces a distinct jkt for distinct keypairs", async () => {
    const a = await createDpopKeyPair();
    const b = await createDpopKeyPair();
    expect(a.jkt).not.toBe(b.jkt);
  });
});
