# 09. Verify a deployment

Work through these in order. Stop at the first failure and check `10-troubleshooting.md`.

## 1. The task is running

```bash
aws ecs describe-services --region us-east-1 --cluster dip-prod --services dip-api \
  --query 'services[0].[runningCount,desiredCount]' --output text
```

Expected: `1  1`.

## 2. The startup log is clean

Get the newest stream and read it:

```bash
STREAM=$(aws logs describe-log-streams --region us-east-1 --log-group-name /ecs/dip-api \
  --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].logStreamName' --output text)
aws logs get-log-events --region us-east-1 --log-group-name /ecs/dip-api \
  --log-stream-name "$STREAM" --limit 50 --query 'events[].message' --output text
```

A healthy start ends with the server listening on port 3000 and no `startup failed` line. Warnings about the PostgreSQL SSL mode are expected and harmless.

## 3. The signers match the pinned keys

The server checks each KMS public key at start. If the pins do not match, it logs `SIGNER_KEY_MISMATCH` and exits. No message means the pins match.

## 4. Health

The health route is public. From inside the VPC, call `http://<TASK_PRIVATE_IP>:3000/v1/health`. It should return `{"status":"ok"}`. Until a load balancer exists, you can check it only from a host inside the VPC.

## 5. One authorized request

The operator key authorizes calls. Retrieve it from Secrets Manager (see `05-secrets.md`), then send a request from inside the VPC:

```bash
curl -sS -H "Authorization: Bearer $OPERATOR_KEY" \
  -H 'Content-Type: application/json' \
  -d @request.json http://<TASK_PRIVATE_IP>:3000/v1/authorize
```

A valid request returns `ALLOW` or `DENY` with a signed decision. An error with no decision means the signer or the database is not working. Do not treat an error as an approval.

## 6. Refusals still work

Send a request for an amount above the authority's limit. The expected answer is `DENY`, with a reason code. If it returns `ALLOW`, stop the service and investigate before anything else.
