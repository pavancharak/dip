// Minimal end-to-end use of the DIP SDK: declare authority, authorize, execute,
// record evidence, and verify. Keys are generated in memory and are for illustration only.
import { DipClient, generateSigningKeyPair, exportEd25519PublicJwk, signAuthority } from "@dip/sdk";

const issuer = generateSigningKeyPair();
const engine = generateSigningKeyPair();
const evidence = generateSigningKeyPair();

const client = new DipClient({
  trustRoots: [
    { keyId: "issuer-key-1", jwk: exportEd25519PublicJwk(issuer.publicKey), status: "ACTIVE" },
    { keyId: "engine-1", jwk: exportEd25519PublicJwk(engine.publicKey), status: "ACTIVE" },
    { keyId: "evidence-1", jwk: exportEd25519PublicJwk(evidence.publicKey), status: "ACTIVE" },
  ],
  engine: { keyId: "engine-1", privateKey: engine.privateKey },
  evidenceSigner: { keyId: "evidence-1", privateKey: evidence.privateKey },
  connectors: new Map([
    [
      "payment.create",
      { id: "demo", execute: async () => ({ status: "SUCCEEDED", externalRef: "demo-1" }) },
    ],
  ]),
  now: () => new Date(),
});

// 1. Declare and publish an authority: payments up to Rs 50,000 (5,000,000 paise).
const declaration = client.createAuthorityDeclaration({
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
client.publishAuthority(signAuthority(declaration, issuer.privateKey));

// 2. Normalize a request for Rs 4,000 and authorize it. The result is ALLOW or DENY.
const request = client.normalizeRequest({
  requestId: "req-1",
  transactionId: "txn-1",
  organizationId: "org-acme",
  tenantId: "tenant-1",
  actor: "payments-agent",
  operation: "payment.create",
  resource: "vendor-42",
  amount: { minor: 400_000, currency: "INR" },
  parameters: { payeeAccount: "acc-9" },
  authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
  policyRef: { policyId: "policy-payments", version: 1 },
  approvalRef: null,
  idempotencyKey: "idem-1",
  protocolVersion: "1.0",
});
const { result, decision } = client.authorize(request);
console.log("authorization:", result);

// 3. Execute through the protected boundary, then record evidence for the attempt.
const attempt = await client.execute(request, decision);
console.log("execution:", attempt.state, attempt.externalRef ?? "");
client.record({ normalized: request, decision, attempt });

// 4. Verify the ledger held by this client.
const report = client.verifyLedger(client.ledgerHead());
console.log("ledger valid:", report.valid, "entries:", report.entries);
if (result !== "ALLOW" || attempt.state !== "SUCCEEDED" || !report.valid) process.exitCode = 1;
