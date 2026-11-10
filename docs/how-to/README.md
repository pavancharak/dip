# How to use DIP

These guides show how to use DIP to authorize and record actions. They assume you have a running DIP server, or you want to try the protocol locally with the SDK. To deploy the server, see `docs/deployment/`.

Read them in order the first time.

| Guide                                                              | You will learn                                                  |
| ------------------------------------------------------------------ | --------------------------------------------------------------- |
| [01-concepts.md](01-concepts.md)                                   | The ideas behind DIP: authority, decisions, approvals, evidence |
| [02-run-the-example.md](02-run-the-example.md)                     | Run a complete example on your machine in a few minutes         |
| [03-declare-an-authority.md](03-declare-an-authority.md)           | Write, sign and publish an authority declaration                |
| [04-authorize-and-execute.md](04-authorize-and-execute.md)         | Send a request, get ALLOW or DENY, and run the action           |
| [05-approvals.md](05-approvals.md)                                 | Route high-value requests to a human approver                   |
| [06-evidence-and-verification.md](06-evidence-and-verification.md) | Record evidence, export it, and verify it independently         |
| [07-use-the-api.md](07-use-the-api.md)                             | Call the HTTP API directly, with keys, scopes and errors        |
| [08-use-the-cli.md](08-use-the-cli.md)                             | Use the `dip` command for files, checks and verification        |
| [09-troubleshooting.md](09-troubleshooting.md)                     | Common problems and how to fix them                             |

## Rules that apply everywhere

- **Only ALLOW lets an action run.** A DENY, an error, or a missing decision means nothing runs. Treat any error as a refusal.
- **Approvals never authorize.** An approval is one input the engine checks. The engine still decides, and it still must return ALLOW.
- **Keys stay out of files you commit.** Key files, API keys and secrets belong in a secret store or a local file you have not added to version control.
- **Amounts are integers in minor units.** For example, `400000` is 4,000.00 INR (paise). Never send floating-point amounts.
