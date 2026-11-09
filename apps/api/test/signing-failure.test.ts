import { sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair, type SigningProvider } from "@dip/crypto";
import { KmsError } from "@dip/kms";
import { DipClient, type DipClientConfig } from "@dip/sdk";
import { createApi, type ApiRequest } from "../src/index.js";

// Drill: the engine must never answer ALLOW when its signature cannot be produced.
// A KMS denial (AccessDenied) or a disabled key both surface here as KmsError.

const NOW = new Date("2026-06-01T12:00:00Z");
const keys = {
  issuer: generateSigningKeyPair(),
  engine: generateSigningKeyPair(),
  evidence: generateSigningKeyPair(),
};

function engineProvider(denied: boolean): SigningProvider {
  return {
    keyId: "engine-1",
    publicJwk: async () => exportEd25519PublicJwk(keys.engine.publicKey),
    sign: async (message) => {
      if (denied) throw new KmsError("KMS_SIGN_FAILED", "KMS call failed (AccessDeniedException)");
      return new Uint8Array(edSign(null, message, keys.engine.privateKey));
    },
  };
}

function config(engine: SigningProvider): DipClientConfig {
  return {
    trustRoots: [
      {
        keyId: "issuer-key-1",
        jwk: exportEd25519PublicJwk(keys.issuer.publicKey),
        status: "ACTIVE",
      },
      { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.engine.publicKey), status: "ACTIVE" },
      {
        keyId: "evidence-1",
        jwk: exportEd25519PublicJwk(keys.evidence.publicKey),
        status: "ACTIVE",
      },
    ],
    engine,
    evidenceSigner: { keyId: "evidence-1", privateKey: keys.evidence.privateKey },
    connectors: new Map([
      [
        "payment.create",
        {
          id: "payments",
          execute: async () => ({ status: "SUCCEEDED" as const, externalRef: "pay-1" }),
        },
      ],
    ]),
    now: () => NOW,
  };
}

function authorityBody(): AuthorityBody {
  return parseAuthorityBody({
    authorityId: "auth-1",
    version: 1,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    issuer: "cfo",
    principal: "cfo",
    agent: "payments-agent",
    permittedActions: ["payment.create"],
    resourceScope: ["vendor-42"],
    maxAmountMinor: 5_000_000,
    currencies: ["INR"],
    approvalAboveMinor: null,
    approvalActions: [],
    approverKeyIds: [],
    validFrom: "2020-01-01T00:00:00Z",
    validUntil: "2100-01-01T00:00:00Z",
    delegatedFrom: null,
    delegationAllowed: false,
    policyId: "policy-1",
    policyVersion: 1,
    protocolVersion: "1.0",
    signatureAlgorithm: "Ed25519",
    signingKeyId: "issuer-key-1",
  });
}

function raw(): Record<string, unknown> {
  return {
    requestId: "req-drill",
    transactionId: "txn-drill",
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: 400_000, currency: "INR" },
    parameters: {},
    authorityRef: { authorityId: "auth-1", version: 1 },
    policyRef: { policyId: "policy-1", version: 1 },
    approvalRef: null,
    idempotencyKey: "idem-drill",
    protocolVersion: "1.0",
  };
}

async function clientWith(engine: SigningProvider): Promise<DipClient> {
  const client = await DipClient.open(config(engine));
  client.publishAuthority(signAuthority(authorityBody(), keys.issuer.privateKey));
  return client;
}

describe("signing failure drill", () => {
  it("control: with a working signer the same request is ALLOW", async () => {
    const client = await clientWith(engineProvider(false));
    const outcome = await client.authorize(client.normalizeRequest(raw()));
    expect(outcome.result).toBe("ALLOW");
  });

  it("a denied KMS signature produces no decision at all", async () => {
    const client = await clientWith(engineProvider(true));
    await expect(client.authorize(client.normalizeRequest(raw()))).rejects.toMatchObject({
      code: "KMS_SIGN_FAILED",
    });
  });

  it("the API returns an error, never an ALLOW body, when signing is denied", async () => {
    const client = await clientWith(engineProvider(true));
    const api = createApi({
      client,
      principals: new Map([
        ["key-operator", { name: "operator", tenantId: "tenant-1", scopes: [] }],
      ]),
      rateLimit: { max: 1000, windowMs: 60_000 },
      clockMs: () => NOW.getTime(),
    });
    const request: ApiRequest = {
      method: "POST",
      path: "/v1/authorize",
      headers: { authorization: "Bearer key-operator" },
      body: raw(),
    };
    const response = await api.handle(request);
    expect(response.status).toBe(500);
    expect(JSON.stringify(response.body)).not.toContain("ALLOW");
  });
});
