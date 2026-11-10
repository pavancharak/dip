# 1. Concepts

## The question DIP answers

Before an agent takes an action, DIP answers one question: **is this action permitted, under a specific authority, right now?** It answers ALLOW or DENY, and nothing else.

## The parts

| Term           | Meaning                                                                                                                                                                |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Authority**  | A signed declaration of what an agent may do: which actions, which resources, up to what amount, in which currencies, and during which dates. Versioned and immutable. |
| **Trust root** | The public key of a party whose signatures the system accepts (an issuer, the engine, the evidence signer, an approver).                                               |
| **Request**    | What an agent wants to do: the actor, the operation, the resource, the amount, and the authority it claims.                                                            |
| **Decision**   | The engine's signed answer, ALLOW or DENY, with reason codes and the checks it ran.                                                                                    |
| **Approval**   | A human's signed decision on a specific request. Routes a case to a person. It never authorizes by itself.                                                             |
| **Execution**  | Running the action through the protected boundary. Only a valid ALLOW decision can start it.                                                                           |
| **Evidence**   | A signed record of what was asked, decided and done. Records form a hash chain, so any change or deletion is detectable.                                               |

## The flow

```
authority ──▶ request ──▶ authorize ──▶ ALLOW? ──▶ execute ──▶ evidence
                              │              │
                              │              └── DENY ──▶ evidence (refusal recorded)
                              │
                        needs approval? ──▶ approval (a person decides) ──▶ re-authorize
```

1. An issuer publishes an authority.
2. The agent sends a request.
3. The engine checks the request against the authority and returns a signed decision.
4. On ALLOW, the boundary executes the action once and records the attempt.
5. Every step, including refusals, is written to the evidence chain.

## Why it is built this way

- **Two outcomes only.** Authorization is ALLOW or DENY. There is no "maybe".
- **Fail closed.** Malformed input is refused. A missing or unverifiable signature is a refusal.
- **Single use.** A decision authorizes one execution. A retry needs a new decision.
- **Independent verification.** Anyone can check the evidence with the public keys, without trusting the server.

## Next

Run the example in [02-run-the-example.md](02-run-the-example.md) to see each part work.
