# 07. Build and push the image

The image is built from a clean export of `main`, not from a working directory. This keeps local changes out of production.

## 1. Export the commit you want

```bash
cd <repo>
git fetch origin +refs/heads/main:refs/remotes/origin/main
SHA=$(git rev-parse --short origin/main)
rm -rf /tmp/dip-build && mkdir /tmp/dip-build
git archive origin/main | tar -x -C /tmp/dip-build
```

## 2. Build for x86_64

Fargate runs `linux/amd64` in this setup, so build that platform explicitly:

```bash
cd /tmp/dip-build
docker build --platform linux/amd64 -t dip-api:$SHA .
```

If your network uses a corporate proxy with its own certificate authority, the build will fail with `self-signed certificate in certificate chain`. Add your CA to the build stage only, the way the sandbox build does. Never disable TLS verification, and never ship your CA in the runtime image. Check the runtime stage afterwards:

```bash
docker run --rm --entrypoint sh dip-api:$SHA -c 'test -e /tmp/<your-ca-file> && echo BAD || echo ok'
```

## 3. Smoke-test the image

```bash
docker run --rm --entrypoint sh dip-api:$SHA -c \
  'node -e "import(\"@dip/sdk\").then(()=>console.log(\"internal packages load\"))"'
```

Expected: `internal packages load`. If you see `ERR_MODULE_NOT_FOUND`, see `10-troubleshooting.md`.

## 4. Push to ECR

```bash
ACC=<ACCOUNT_ID>
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin $ACC.dkr.ecr.us-east-1.amazonaws.com
docker tag dip-api:$SHA $ACC.dkr.ecr.us-east-1.amazonaws.com/dip-api:$SHA
docker push $ACC.dkr.ecr.us-east-1.amazonaws.com/dip-api:$SHA
```

The repository uses **immutable tags**. Each commit gets its own tag, and a pushed tag cannot be overwritten. To fix a bad image, build a new commit and push its tag.

## Notes

- Never use the `latest` tag in the task definition.
- The first push can show partial output. Check the final line for `digest:`.
- If a push fails with `not authorized to perform: ecr:BatchGetImage`, the deployer policy is missing that action. See `04-iam-roles.md`.
