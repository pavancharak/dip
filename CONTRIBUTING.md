# Contributing to DIP

Thank you for considering a contribution. DIP is a protocol: changes to behaviour are changes to a specification, and they need care.

## Before you start

- For anything larger than a small fix, open an issue first. Describe the problem and the change you propose.
- For security problems, do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Setup

```bash
pnpm install --frozen-lockfile
pnpm check
```

Requires Node.js 22 and pnpm 10. `pnpm check` runs the build, typecheck, lint, format check and tests. It must pass before you open a pull request.

To run the real-PostgreSQL test as well, set `DIP_TEST_PG_URL` to a PostgreSQL 14+ server. CI does this with a PostgreSQL 16 service.

## Making a change

1. Branch from `main`. Keep each pull request focused on one change.
2. Write or update tests. Tests must be deterministic: inject the clock and any randomness, do not read system time in protocol logic.
3. If the change alters behaviour that a specification section describes, update that section in `docs/spec/` in the same pull request. Keep the section's status line accurate.
4. If the change alters a rule that the conformance fixtures check, regenerate the fixtures and explain why in the pull request. A failing fixture is a finding, not an inconvenience.
5. Record non-obvious design choices in `docs/ARCHITECTURE_DECISIONS.md`.
6. Update `CHANGELOG.md` under _Unreleased_.
7. Commit messages explain why, not only what.

## Rules the project keeps

- **Two authorization outcomes only.** Do not add a third outcome, under any name.
- **No AI-based authorization.** Authorization is deterministic rules and signed data.
- **No floating-point money.** Amounts are integer minor units.
- **No mutable evidence.** Do not add update or delete paths for evidence or authority records.
- **No secrets in the repository.** Keys, tokens and passwords never go in source control, examples, fixtures or tests. Test keys are generated in the test.
- **The verifier stays independent.** `packages/verifier` depends only on `@dip/crypto`.
- **Do not claim what is not tested.** Documentation states what is verified and what is not.

## Pull requests

- Describe what changed and how you verified it. Include the `pnpm check` result.
- Keep unrelated formatting changes out of the diff.
- A reviewer will check protocol-visible changes against the specification and the conformance fixtures.

## Licensing

By contributing, you agree that your contribution is licensed under the project's license (Apache-2.0, see [LICENSE](LICENSE)).

## Conduct

Be respectful and constructive. Keep discussion on the work, not on the people. A separate code of conduct is not yet adopted; maintainers will decide on one before the project accepts external contributions at scale.
