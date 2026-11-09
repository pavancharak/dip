// Executable examples. Each one runs the public SDK end to end and asserts the
// outcome, so a clean installation that prints "all examples passed" has
// reproduced the protocol behaviour. Keys here are generated fresh and are not for production.
import assert from "node:assert/strict";
import {
  DipClient,
  generateSigningKeyPair,
  exportEd25519PublicJwk,
  signAuthority,
  signRevocation,
} from "@dip/sdk";

const keys = {
  issuer: generateSigningKeyPair(),
  engine: generateSigningKeyPair(),
  evidence: generateSigningKeyPair(),
};
let connectorCalls = 0;
const trustRoots = [
  { keyId: "issuer-key-1", jwk: exportEd25519PublicJwk(keys.issuer.publicKey), status: "ACTIVE" },
  { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.engine.publicKey), status: "ACTIVE" },
  { keyId: "evidence-1", jwk: exportEd25519PublicJwk(keys.evidence.publicKey), status: "ACTIVE" },
];
const client = new DipClient({
  trustRoots,
  engine: { keyId: "engine-1", privateKey: keys.engine.privateKey },
  evidenceSigner: { keyId: "evidence-1", privateKey: keys.evidence.privateKey },
  connectors: new Map([
    [
      "payment.create",
      {
        id: "example-payments",
        execute: async () => {
          connectorCalls += 1;
          return { status: "SUCCEEDED", externalRef: `pay-${String(connectorCalls)}` };
        },
      },
    ],
  ]),
  now: () => new Date(),
});

// A vendor-payments authority: up to ₹50,000 (5,000,000 paise), INR only.
const body = client.createAuthorityDeclaration({
  authorityId: "auth-vendor-payments",
  version: 1,
  organizationId: "org-acme",
  tenantId: "tenant-1",
  issuer: "cfo-office",
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
  policyId: "policy-payments",
  policyVersion: 1,
  protocolVersion: "1.0",
  signatureAlgorithm: "Ed25519",
  signingKeyId: "issuer-key-1",
});
client.publishAuthority(signAuthority(body, keys.issuer.privateKey));

function request(amountMinor, idempotencyKey) {
  return client.normalizeRequest({
    requestId: `req-${idempotencyKey}`,
    transactionId: `txn-${idempotencyKey}`,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: amountMinor, currency: "INR" },
    parameters: { payeeAccount: "acc-9" },
    authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
    policyRef: { policyId: "policy-payments", version: 1 },
    approvalRef: null,
    idempotencyKey,
    protocolVersion: "1.0",
  });
}

const results = [];
function record(name, ok) {
  results.push({ name, ok });
  process.stdout.write(`${ok ? "PASS" : "FAIL"}  ${name}\n`);
}

// Example 1: authorized payment, executed, evidenced, and independently verified.
const ok = request(4_000_000, "ex1");
const allow = client.authorize(ok);
const executed = await client.execute(ok, allow.decision);
client.record({ normalized: ok, decision: allow.decision, attempt: executed });
const bundle = {
  format: "dip-evidence-bundle",
  formatVersion: 1,
  entries: client.ledgerLines(),
  expectedHead: client.ledgerHead(),
  requests: [{ body: ok.request, requestDigest: ok.requestDigest }],
  decisions: [allow.decision],
  authorities: [client.getAuthority("auth-vendor-payments", 1)],
  approvals: [],
};
record(
  "1. ₹40,000 payment is ALLOW, executes once, and verifies as VALID",
  allow.result === "ALLOW" &&
    executed.state === "SUCCEEDED" &&
    client.verifyBundle(bundle).verdict === "VALID" &&
    connectorCalls === 1,
);

// Example 2: over the limit is DENY and never reaches the connector.
const big = request(8_000_000, "ex2");
const deny = client.authorize(big);
const refused = await client.execute(big, deny.decision);
record(
  "2. ₹80,000 payment is DENY and the connector is not called",
  deny.result === "DENY" && refused.state === "REFUSED" && connectorCalls === 1,
);

// Example 3: tampered evidence is detected by the independent verifier.
const tampered = JSON.parse(JSON.stringify(bundle));
tampered.entries = [tampered.entries[0].replace("txn-ex1", "txn-evil")];
record(
  "3. tampered evidence is detected as INVALID",
  client.verifyBundle(tampered).verdict === "INVALID",
);

// Example 4: revoked authority stops execution of a previously ALLOW decision.
client.revokeAuthority(
  signRevocation(
    {
      authorityId: "auth-vendor-payments",
      version: 1,
      revokedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      signingKeyId: "issuer-key-1",
    },
    keys.issuer.privateKey,
  ),
);
const late = await client.execute(ok, allow.decision);
record(
  "4. revoked authority: the earlier ALLOW decision no longer executes",
  late.state === "REFUSED" && late.reasonCode === "AUTHORITY_REVOKED" && connectorCalls === 1,
);

const failed = results.filter((r) => !r.ok);
process.stdout.write(
  `\n${String(results.length - failed.length)}/${String(results.length)} examples passed\n`,
);
try {
  assert.equal(failed.length, 0);
} catch {
  process.exitCode = 1;
}
