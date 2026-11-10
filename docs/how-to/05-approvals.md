# 5. Approvals

Some requests should go to a person. An approval is that person's signed decision on one specific request.

## When approval is needed

An authority requires approval when either:

- the amount is above `approvalAboveMinor`, or
- the operation is listed in `approvalActions`.

Without an approval, such a request is DENY with `APPROVAL_REQUIRED`.

## The flow

1. **Authorize** the request. It returns DENY with `APPROVAL_REQUIRED`.
2. **Request an approval** for that exact request. The approval is bound to the request's content.
3. **The approver decides**, and signs the decision with an approver key listed in `approverKeyIds`.
4. **Authorize again** with the approval's ID in `approvalRef`. The engine checks the approval and can return ALLOW.
5. **Execute** with the new decision.

## Request an approval

Requesting an approval needs a key with the `approver` scope.

```bash
curl -sS -X POST "$DIP_URL/v1/approvals" \
  -H "Authorization: Bearer $DIP_API_KEY" \
  -H "Content-Type: application/json" \
  --data @approval-request.json
```

The binding names the approval ID, the request's digest, the authority and the policy, and the approver key IDs allowed to decide.

## Check its state

```bash
curl -sS "$DIP_URL/v1/approvals/<approval-id>" -H "Authorization: Bearer $DIP_API_KEY"
```

States are `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED` and `REVOKED`. Only `APPROVED` can satisfy a requirement, and only while it has not expired or been revoked.

## Decide

An approver signs one of three decisions: approve, reject, or revoke a previous approval.

```bash
curl -sS -X POST "$DIP_URL/v1/approvals/<approval-id>/approve" \
  -H "Authorization: Bearer $APPROVER_KEY" \
  -H "Content-Type: application/json" \
  --data @approval-decision.json
```

Replace `approve` with `reject` or `revoke` as needed. The approver's key needs the `approver` scope. The decision must name the same approval ID, and its action must match the route.

## What an approval does and does not do

- An approval **never authorizes by itself**. It is one input. The engine still checks the authority, the amount, the dates and the policy.
- An approval is bound to **one exact request**. Changing any field, including the amount or the resource, makes it invalid. The engine refuses the request, and the reason codes say why.
- An approval **cannot raise the limit**. If the amount exceeds `maxAmountMinor`, an approval does not help. The request is DENY.
- A **revoked** approval stops working immediately, including for requests already authorized but not yet executed. The boundary re-checks it.
- An approval from a key **not** listed in `approverKeyIds` is refused.

## Do not

- Do not reuse an approval for a different request, even a similar one.
- Do not approve on someone else's behalf. Each approver signs with their own key.
- Do not treat "approved" in your own system as permission to act. Only ALLOW from the engine lets an action run.
