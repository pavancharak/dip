# 08. Deploy

This covers the ECS side: the cluster, the task definition, the service and the logs.

## Resources

| Resource                | Name                                               |
| ----------------------- | -------------------------------------------------- |
| Cluster                 | `dip-prod`                                         |
| Task definition family  | `dip-api`                                          |
| Service                 | `dip-api`, desired count 1                         |
| Log group               | `/ecs/dip-api`                                     |
| Service security group  | `dip-api-service` (no inbound rules)               |
| Database security group | `dip-db` (allows 5432 from `dip-api-service` only) |
| Subnets                 | All subnets of the default VPC, public IPs enabled |

## The task definition

The template is `deployment/aws/task-definition.json`. It has placeholders for the account, the image, the execution role and the three secret ARNs. Fill them in at deploy time and do not commit the filled file.

Key settings:

- `requiresCompatibilities`: `FARGATE`, `networkMode`: `awsvpc`, 512 CPU, 1024 MB
- `taskRoleArn`: `dip-api-signer-prod`
- `executionRoleArn`: `dip-ecs-execution-prod`
- `user`: `node`, `readonlyRootFilesystem`: true
- `secrets`: three entries, `DIP_CONFIG_JSON`, `DIP_PG_URL`, `DIP_OPERATOR_KEY`
- `logConfiguration`: `awslogs` to `/ecs/dip-api`

Fill and register:

```bash
python3 - <ACCOUNT_ID> <IMAGE_TAG> <SECRET_ARN_CONFIG> <SECRET_ARN_PG> <SECRET_ARN_KEY> <<'PY'
import json,sys
acc,tag,cfg,pg,key=sys.argv[1:6]
t=json.load(open('deployment/aws/task-definition.json'))
t['taskRoleArn']=f'arn:aws:iam::{acc}:role/dip-api-signer-prod'
t['executionRoleArn']=f'arn:aws:iam::{acc}:role/dip-ecs-execution-prod'
c=t['containerDefinitions'][0]
c['image']=f'{acc}.dkr.ecr.us-east-1.amazonaws.com/dip-api:{tag}'
m={'<CONFIG_SECRET_ARN>':cfg,'<PG_URL_SECRET_ARN>':pg,'<OPERATOR_KEY_SECRET_ARN>':key}
for s in c['secrets']: s['valueFrom']=m[s['valueFrom']]
json.dump(t,open('/tmp/dip-task-def.json','w'),indent=2)
PY
aws ecs register-task-definition --region us-east-1 --cli-input-json file:///tmp/dip-task-def.json \
  --query 'taskDefinition.taskDefinitionArn' --output text
```

Each registration creates a new revision (`dip-api:1`, `dip-api:2`, and so on). Use the revision number in the next step.

## Cluster, log group and service (first time only)

```bash
aws ecs create-cluster --region us-east-1 --cluster-name dip-prod
aws logs create-log-group --region us-east-1 --log-group-name /ecs/dip-api
```

Create the service security group with no inbound rules, then allow the database to accept it:

```bash
VPC=$(aws ec2 describe-vpcs --region us-east-1 --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SVC_SG=$(aws ec2 create-security-group --region us-east-1 --group-name dip-api-service \
  --description "DIP API tasks, no inbound" --vpc-id $VPC --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region us-east-1 --group-id <DB_SG_ID> \
  --protocol tcp --port 5432 --source-group $SVC_SG
```

Create the service:

```bash
SUBNETS=$(aws ec2 describe-subnets --region us-east-1 --filters Name=vpc-id,Values=$VPC \
  --query 'Subnets[].SubnetId' --output text | tr '\t' ',')
aws ecs create-service --region us-east-1 --cluster dip-prod --service-name dip-api \
  --task-definition dip-api:<REVISION> --desired-count 1 --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SVC_SG],assignPublicIp=ENABLED}"
```

## Update to a new image

Register a new revision with the new image tag, then point the service at it:

```bash
aws ecs update-service --region us-east-1 --cluster dip-prod --service dip-api \
  --task-definition dip-api:<NEW_REVISION>
```

## Force a new deployment

Use this after a secret changes, so the task reads the new value:

```bash
aws ecs update-service --region us-east-1 --cluster dip-prod --service dip-api --force-new-deployment
```

## Stop the service

```bash
aws ecs update-service --region us-east-1 --cluster dip-prod --service dip-api --desired-count 0
```

Stopping leaves the cluster, the task definitions and the database in place.

## Watch a deployment

```bash
aws ecs describe-services --region us-east-1 --cluster dip-prod --services dip-api \
  --query 'services[0].[runningCount,pendingCount,events[0].message]' --output text
```

Wait for `has reached a steady state`. Then read the logs (see `09-verify.md`).

## Known gap: no load balancer

The service has no load balancer and its security group allows no inbound traffic, so nothing outside the VPC can call it. Adding an Application Load Balancer, with its own security group and a rule to the service group, is the next infrastructure step.
