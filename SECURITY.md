# Security Policy

## Reporting a vulnerability

Do not open a public issue or pull request for a security problem.

Report it privately through GitHub Security Advisories on this repository: the **Security** tab, then **Report a vulnerability**. Include:

- the affected component and version or commit,
- steps to reproduce, or a proof of concept,
- the impact you expect,
- whether you have shared it with anyone else.

Maintainers will acknowledge reports and discuss a fix privately. No response time is guaranteed yet, because the project has no dedicated security team.

## Scope

In scope:

- Authorization bypass, including any way to execute without a verified ALLOW decision.
- Execution outside the boundary, or a connector making an authorization decision.
- Replay, duplicate execution, or approval substitution.
- Cryptographic misuse: signature forgery, malleability, domain-separation failures.
- Evidence or ledger tampering that verifies as VALID.
- Verifier false positives (INVALID evidence reported as VALID).
- Cross-tenant access through the API or storage.

Out of scope, or handled as hardening rather than vulnerabilities:

- Compromise of a trusted signing key that the operator has not revoked (see [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), T9).
- Truncation of the ledger tail when no external head is recorded (T11).
- An in-process caller invoking a connector directly (T14).
- Problems in third-party dependencies, which should be reported to their maintainers.

## Supported versions

DIP has no released version yet. Only the `main` branch is supported. Once releases exist, this section will list supported versions.

## Known limitations

The project has had no external security review. The threat model lists residual risks. Do not rely on DIP for production decisions until the open items in [docs/RELEASE-AUDIT.md](docs/RELEASE-AUDIT.md) are resolved.
