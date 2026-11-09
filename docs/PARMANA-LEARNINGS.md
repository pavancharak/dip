# Lessons Carried Into DIP from Parmana

Status: adopted. Source: Parmana `DECISIONS.md`, `04-INCIDENTS-LOG.md` (INC-1 to INC-12).

DIP is a standalone protocol. It does not import Parmana code, share keys, or depend on
Parmana to operate or verify evidence. This document records lessons, not code.

## 1. Lessons and the DIP rule that follows

| Parmana incident                                                                  | Lesson                                                     | DIP rule                                                                                                                                                     |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| INC-1: private signing key committed and public                                   | Keys in git are permanently compromised                    | `keys/`, `*.pem`, `*.key` are git-ignored. Keys are never committed. Production keys belong in a KMS/HSM (later phase).                                      |
| INC-2: fake "hash" (base64 of content) shipped in a release tag                   | A security primitive that binds nothing is worse than none | Hashing and signing come only from `packages/crypto`, with known-answer tests. No stubs exported from the public API.                                        |
| INC-3: ephemeral signing keys per instance                                        | Verification fails silently across instances               | Keys are explicit inputs. No key is generated implicitly by a constructor. Cross-instance verification is tested.                                            |
| INC-4: TypeScript parameter bivariance hid a wrong-arity provider                 | Type checks alone do not prove interface conformance       | Provider interfaces get conformance tests. Each crypto provider has real tests, not only type checks.                                                        |
| INC-5: return-shape change silently broke examples                                | Examples and docs are consumers too                        | CI runs example and conformance scripts, not only unit tests (planned in conformance phase).                                                                 |
| INC-6: policy evaluated caller-declared inputs never bound to the executed action | Authorization must check the same data that executes       | Authorization inputs and execution inputs come from one canonical object. The DIP spec requires a single decision object hashed once and bound to execution. |
| INC-7: audit rows durable but unsigned                                            | Durable is not tamper-evident                              | Every ledger entry is signed and hash-chained at write time, including refusals.                                                                             |
| INC-8: keys on a feature branch, purge incomplete                                 | History rewrites do not fully remove leaked material       | Treat any leaked key as compromised and rotate. Do not rely on history purges.                                                                               |
| INC-9: `main` replaced by a parentless commit                                     | Branch protection is required                              | `main` is protected: force pushes blocked, PR required, CI required. Only the owner can change integrations with write access.                               |
| INC-10: SDK version constant out of sync with manifest                            | Versions must have one source                              | A single version source, read from the package manifest.                                                                                                     |
| INC-11: new required env var shipped before provisioning                          | Config drift breaks production loudly                      | Required configuration is validated during build. Deployments fail the build, not production.                                                                |
| INC-12: Dependabot merges broke the lockfile and changed major versions           | Automated dependency PRs need checks and review            | Dependabot PRs merge only with green CI. Lockfile changes come only from `pnpm` resolution, not hand edits.                                                  |

## 2. Rules inherited from Parmana's governance

1. **No claim phrases.** DIP docs must not use Parmana's forbidden phrases, such as
   Parmana's forbidden claim phrases, as listed in its DECISIONS.md section 2.4 (not repeated here).
   Describe only behaviour a test demonstrates.
2. **Patent-risk review before implementation.** Parmana classifies several mechanisms
   as PATENT-RISK (signed execution audit trail, maker-checker enforcement at execution
   time, signal/intent binding, credential isolation). DIP designs in these areas (approval,
   execution boundary, evidence, ledger) must be reviewed by the owner or patent counsel
   before they are implemented. This review is not complete. Nothing here is legal advice.
3. **Classification of content.** New DIP files are public by default. Any file with
   secrets, customer data, or internal planning material stays out of the repository.
4. **Evidence is generated on purpose.** Tests write to temporary directories. Committed
   evidence is regenerated only through an explicit command (Parmana INC-follow-up).

## 3. Design consequences for Phase 1 and later

- Canonical encoding and hashing: done (`packages/crypto`, spec section 3).
- Ledger entries and refusal records are signed at write time (spec section 8, pending).
- Decision objects bind policy inputs and execution inputs by a single digest (spec
  sections 4 and 6, pending).
- Conformance vectors are generated and checked in CI (`packages/conformance`, pending).
- Independent verifier does not import the reference implementation (spec section 9, pending).

## 4. Open questions for the owner

1. Confirm the DIP licence (Apache-2.0 is a proposal).
2. Confirm whether patent counsel should review the Phase 1 approval and evidence designs
   before implementation.
3. Confirm whether DIP may reuse Parmana's public ideas (not code) in its specification.
