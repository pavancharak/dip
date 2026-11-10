# Releasing DIP

This describes how a release is cut. It follows the `v1.0.0` release.

## Before tagging

1. The changelog has a section for the version, with the changes and known limits.
2. `pnpm check` passes on `main`.
3. The documentation site builds (`pnpm exec vitepress build docs`).
4. No account IDs, keys or secrets appear in the diff. Run `git log -p` and search for account and key patterns before publishing.

## Merging to main

`main` is protected by a repository ruleset that requires pull requests, passing checks, and signed commits.

- Use **Squash and merge** in the GitHub web interface. GitHub signs commits made there.
- API merges and rebase merges cannot satisfy the signed-commit rule, so they are refused. This is expected.

## Tagging and publishing

1. Open **Releases → Draft a new release**.
2. Choose the tag, create it on publish, and target `main`.
3. Use the version as the title, for example `DIP v1.0.0`.
4. Paste the changelog section for that version as the description.
5. Publish.

Check the result: the tag should point at the commit you expect.

```bash
git fetch origin --tags
git rev-parse --short v1.0.0^{commit}
git rev-parse --short origin/main
```

Both commands should print the same hash.

## After publishing

- Make sure the default branch is `main` (Settings → General).
- Confirm the documentation site updated after the merge.
- Delete merged branches, but keep any branch with commits that are not on `main`.

## Versioning

The protocol version and the software version are separate. Change the protocol version only when decisions, evidence or verification change in a way that breaks existing records. Follow `docs/spec/17-versioning.md`.
