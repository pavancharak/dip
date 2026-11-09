import { describe, expect, it } from "vitest";
import { DipError, TrustRootSet } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { ApprovalStore, signApprovalDecision } from "../src/index.js";

const DIGEST = "a".repeat(64);
const REQ = "2026-06-01T11:00:00Z";
const EXP = "2026-06-01T13:00:00Z";

function setup(): { store: ApprovalStore; key: ReturnType<typeof generateSigningKeyPair> } {
  const key = generateSigningKeyPair();
  const trust = new TrustRootSet();
  trust.add({ keyId: "approver-1", jwk: exportEd25519PublicJwk(key.publicKey), status: "ACTIVE" });
  return { store: new ApprovalStore(trust), key };
}

function binding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    approvalId: "appr-1",
    organizationId: "org-acme",
    requestDigest: DIGEST,
    authorityRef: { authorityId: "auth-1", version: 1 },
    policyRef: { policyId: "policy-1", version: 1 },
    approverKeyId: "approver-1",
    requestedAt: REQ,
    expiresAt: EXP,
    ...overrides,
  };
}

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof DipError ? err.code : "UNEXPECTED_ERROR";
  }
  return undefined;
}

const expectation = {
  organizationId: "org-acme",
  requestDigest: DIGEST,
  authorityRef: { authorityId: "auth-1", version: 1 },
  policyRef: { policyId: "policy-1", version: 1 },
  approverKeyIds: ["approver-1"],
};

describe("approval store", () => {
  it("starts PENDING and blocks authorization until approved", () => {
    const { store } = setup();
    store.request(binding(), new Date(REQ));
    expect(store.verifyFor("appr-1", expectation, new Date(REQ))).toBe("APPROVAL_PENDING");
  });

  it("rejects requests with an inverted validity window", () => {
    const { store } = setup();
    expect(codeOf(() => store.request(binding({ expiresAt: REQ }), new Date(REQ)))).toBe(
      "INVALID_FIELD",
    );
  });

  it("refuses a request whose key is not trusted", () => {
    const { store } = setup();
    expect(codeOf(() => store.request(binding({ approverKeyId: "nobody" }), new Date(REQ)))).toBe(
      "APPROVER_KEY_UNKNOWN",
    );
  });

  it("refuses a duplicate approval id", () => {
    const { store } = setup();
    store.request(binding(), new Date(REQ));
    expect(codeOf(() => store.request(binding(), new Date(REQ)))).toBe("APPROVAL_ALREADY_EXISTS");
  });

  it("expires pending approvals by time without mutating the record", () => {
    const { store } = setup();
    store.request(binding(), new Date(REQ));
    expect(store.status("appr-1", new Date(EXP))).toBe("EXPIRED");
    expect(store.history("appr-1")).toHaveLength(1);
  });

  it("records an audit history of transitions", () => {
    const { store, key } = setup();
    store.request(binding(), new Date(REQ));
    store.decide(
      signApprovalDecision(
        {
          approvalId: "appr-1",
          action: "APPROVE",
          approverKeyId: "approver-1",
          decidedAt: "2026-06-01T11:30:00Z",
        },
        key.privateKey,
      ),
      new Date("2026-06-01T11:30:00Z"),
    );
    expect(store.history("appr-1").map((e) => e.stateAfter)).toEqual(["PENDING", "APPROVED"]);
  });

  it("refuses a decision after the approval has expired", () => {
    const { store, key } = setup();
    store.request(binding(), new Date(REQ));
    const late = signApprovalDecision(
      {
        approvalId: "appr-1",
        action: "APPROVE",
        approverKeyId: "approver-1",
        decidedAt: "2026-06-01T13:30:00Z",
      },
      key.privateKey,
    );
    expect(codeOf(() => store.decide(late, new Date("2026-06-01T13:30:00Z")))).toBe(
      "APPROVAL_EXPIRED",
    );
  });

  it("refuses a decision timestamped in the future", () => {
    const { store, key } = setup();
    store.request(binding(), new Date(REQ));
    const future = signApprovalDecision(
      {
        approvalId: "appr-1",
        action: "APPROVE",
        approverKeyId: "approver-1",
        decidedAt: "2026-06-01T12:00:00Z",
      },
      key.privateKey,
    );
    expect(codeOf(() => store.decide(future, new Date("2026-06-01T11:30:00Z")))).toBe(
      "INVALID_FIELD",
    );
  });

  it("refuses binding mismatch on authority version", () => {
    const { store } = setup();
    store.request(binding(), new Date(REQ));
    expect(
      store.verifyFor(
        "appr-1",
        { ...expectation, authorityRef: { authorityId: "auth-1", version: 2 } },
        new Date(REQ),
      ),
    ).toBe("APPROVAL_BINDING_MISMATCH");
  });

  it("refuses an approver outside the authority's approver set", () => {
    const { store, key } = setup();
    store.request(binding(), new Date(REQ));
    store.decide(
      signApprovalDecision(
        {
          approvalId: "appr-1",
          action: "APPROVE",
          approverKeyId: "approver-1",
          decidedAt: "2026-06-01T11:30:00Z",
        },
        key.privateKey,
      ),
      new Date("2026-06-01T11:30:00Z"),
    );
    expect(
      store.verifyFor(
        "appr-1",
        { ...expectation, approverKeyIds: ["someone-else"] },
        new Date("2026-06-01T11:31:00Z"),
      ),
    ).toBe("APPROVER_NOT_AUTHORIZED");
  });
});
