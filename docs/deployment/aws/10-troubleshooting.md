# 10. Troubleshooting

Each entry shows the symptom, the cause we found, and the fix.

## `ERR_MODULE_NOT_FOUND: Cannot find package '@dip/sdk'`

**Cause:** the runtime image was built with `pnpm prune --prod`, which removed the links to the internal packages.
**Fix:** build with `pnpm deploy` (see `deployment/aws/` and the Dockerfile). Confirm with the smoke test in `07-build-and-push.md`.

## `self-signed certificate in certificate chain`

**Cause:** the server connects to the database over TLS, and Node does not trust the RDS certificate authority.
**Fix:** the image must include `deployment/aws/rds-global-bundle.pem` and set `NODE_EXTRA_CA_CERTS` to it. Check both with `docker run --rm --entrypoint sh <image> -c 'ls -l /app/rds-global-bundle.pem; echo $NODE_EXTRA_CA_CERTS'`.

## `ECONNREFUSED` or a connection timeout to port 5432

**Cause:** the task cannot reach the database. Usual reasons: the database is not `available` yet, the database security group does not allow the service group, or the task is not in the VPC.
**Fix:** check the database status, then check that `dip-db` allows 5432 from `dip-api-service`.

## `Unable to assume the service linked role`

**Cause:** the ECS service-linked role does not exist yet, or was created seconds ago.
**Fix:** create it (see `04-iam-roles.md`), wait about a minute, then retry.

## `AccessDeniedException` on an ECR or IAM action

**Cause:** the deployer policy is missing the action.
**Fix:** ask an administrator to add it. Do not work around it with another identity.

## `SIGNER_KEY_MISMATCH`

**Cause:** the KMS public key does not match the pinned trust root in the configuration.
**Fix:** re-download the key's public key from the console and recompute the JWK (see `03-kms-keys.md`). Update `dip/prod/config`, then force a new deployment.

## `SIGNER_ROOT_MISSING`

**Cause:** no ACTIVE trust root exists for the signer's `keyId`.
**Fix:** add the root to `trustRoots` in the configuration, with `status` `ACTIVE`.

## `KMS_SIGN_FAILED` or `AccessDeniedException` from KMS

**Cause:** the task role cannot sign with the key. Either the role's inline policy or the key policy is missing the statement.
**Fix:** check both (see `03-kms-keys.md` and `04-iam-roles.md`). A denied signature is refused by design, so the service returns an error rather than ALLOW.

## `INVALID_CONFIG: at least one trust root is required`

**Cause:** the configuration secret is empty or has no `trustRoots`. Also seen when testing with dummy secret values.
**Fix:** write the full configuration to `dip/prod/config`.

## `CannotPullContainerError` or `no basic auth credentials`

**Cause:** the execution role cannot pull from ECR, or the image tag does not exist.
**Fix:** confirm the tag with `aws ecr describe-images --repository-name dip-api`, and confirm the execution role has the ECS task execution policy.

## Task starts and exits with code 1, and no log stream appears

**Cause:** the container failed before writing output, or the awslogs driver could not create a stream.
**Fix:** check the stop reason with `aws ecs describe-tasks`, then list streams with `aws logs describe-log-streams`. Streams can appear a few seconds after the task starts, so retry before concluding there are none.

## Image build fails with `self-signed certificate in certificate chain`

**Cause:** the build machine is behind a proxy with its own CA.
**Fix:** add that CA in the build stage only (see `07-build-and-push.md`).

## Git refuses to commit a `.pem` file

**Cause:** `.gitignore` and `.dockerignore` exclude `*.pem` so private keys are never committed or shipped.
**Fix:** the only allowed exception is `deployment/aws/rds-global-bundle.pem`, which is a public certificate. Do not add exceptions for keys.
