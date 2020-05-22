# AWS CUSTODIAN SCHEMA DIFF:

👉👉 *ANY ITEMS WITH ⭐ NEXT TO THEM ARE NEW SINCE LAST RELEASE*

👉👉 *ANY ITEMS WITH ❌ NEXT TO THEM ARE REMOVED SINCE LAST RELEASE*

# 


AWS resources in c7n v0.8.46.1:    **170**

AWS resources in c7n v0.9.1:    **170**
# 


### ⭐ New Items:

    Resources:  0
    Actions:  10
    Filters:  88


### ❌ Removed Items:

    Resources:  0
    Actions:  0
    Filters:  0




# 


# Schema:



### aws.account:
```
  actions:
⭐  - set-emr-block-public-access
  filters:
⭐  - emr-block-public-access

```

# 




### aws.app-elb-target-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.backup-plan:
```
  filters:
⭐  - config-compliance

```

# 




### aws.backup-vault:
```
  filters:
⭐  - config-compliance

```

# 




### aws.batch-compute:
```
  filters:
⭐  - config-compliance

```

# 




### aws.batch-definition:
```
  filters:
⭐  - config-compliance

```

# 




### aws.cache-cluster:
```
  filters:
⭐  - config-compliance

```

# 




### aws.cache-subnet-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.codecommit:
```
  filters:
⭐  - config-compliance

```

# 




### aws.codepipeline:
```
  actions:
⭐  - delete
  filters:
⭐  - config-compliance

```

# 




### aws.config-recorder:
```
  filters:
⭐  - config-compliance

```

# 




### aws.config-rule:
```
  filters:
⭐  - config-compliance

```

# 




### aws.customer-gateway:
```
  filters:
⭐  - config-compliance

```

# 




### aws.dlm-policy:
```
  filters:
⭐  - config-compliance

```

# 




### aws.dms-endpoint:
```
  filters:
⭐  - config-compliance

```

# 




### aws.dms-instance:
```
  filters:
⭐  - config-compliance

```

# 




### aws.dynamodb-table:
```
  actions:
⭐  - set-continuous-backup
  filters:
⭐  - continuous-backup

```

# 




### aws.ecr:
```
  filters:
⭐  - config-compliance

```

# 




### aws.ecs:
```
  filters:
⭐  - config-compliance

```

# 




### aws.ecs-service:
```
  filters:
⭐  - config-compliance

```

# 




### aws.ecs-task:
```
  filters:
⭐  - config-compliance

```

# 




### aws.ecs-task-definition:
```
  filters:
⭐  - config-compliance

```

# 




### aws.efs:
```
  filters:
⭐  - config-compliance

```

# 




### aws.efs-mount-target:
```
  filters:
⭐  - config-compliance

```

# 




### aws.eks:
```
  filters:
⭐  - config-compliance

```

# 




### aws.elasticache-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.elasticbeanstalk:
```
  filters:
⭐  - config-compliance

```

# 




### aws.elasticbeanstalk-environment:
```
  filters:
⭐  - config-compliance

```

# 




### aws.elasticsearch:
```
  filters:
⭐  - config-compliance

```

# 




### aws.emr:
```
  filters:
⭐  - config-compliance

```

# 




### aws.emr-security-configuration:
```
  filters:
⭐  - config-compliance

```

# 




### aws.event-rule:
```
  actions:
⭐  - auto-tag-user
⭐  - copy-related-tag
⭐  - mark-for-op
⭐  - remove-tag
⭐  - tag
  filters:
⭐  - config-compliance
⭐  - marked-for-op

```

# 




### aws.firehose:
```
  filters:
⭐  - config-compliance

```

# 




### aws.fsx:
```
  filters:
⭐  - config-compliance

```

# 




### aws.gamelift-build:
```
  filters:
⭐  - config-compliance

```

# 




### aws.gamelift-fleet:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-catalog:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-classifier:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-connection:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-crawler:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-database:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-dev-endpoint:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-job:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-ml-transform:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-security-configuration:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-trigger:
```
  filters:
⭐  - config-compliance

```

# 




### aws.glue-workflow:
```
  filters:
⭐  - config-compliance

```

# 




### aws.healthcheck:
```
  filters:
⭐  - config-compliance

```

# 




### aws.hostedzone:
```
  filters:
⭐  - config-compliance

```

# 




### aws.identity-pool:
```
  filters:
⭐  - config-compliance

```

# 




### aws.iot:
```
  filters:
⭐  - config-compliance

```

# 




### aws.kafka:
```
  filters:
⭐  - config-compliance

```

# 




### aws.key-pair:
```
  actions:
⭐  - delete
  filters:
⭐  - unused

```

# 




### aws.kinesis:
```
  filters:
⭐  - config-compliance

```

# 




### aws.kinesis-analytics:
```
  filters:
⭐  - config-compliance

```

# 




### aws.kms:
```
  filters:
⭐  - config-compliance

```

# 




### aws.kms-key:
```
  filters:
⭐  - config-compliance

```

# 




### aws.lambda-layer:
```
  filters:
⭐  - config-compliance

```

# 




### aws.log-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.message-broker:
```
  filters:
⭐  - config-compliance

```

# 




### aws.nat-gateway:
```
  filters:
⭐  - config-compliance

```

# 




### aws.opswork-cm:
```
  filters:
⭐  - config-compliance

```

# 




### aws.opswork-stack:
```
  filters:
⭐  - config-compliance

```

# 




### aws.peering-connection:
```
  filters:
⭐  - config-compliance

```

# 




### aws.rds-cluster:
```
  filters:
⭐  - config-compliance

```

# 




### aws.rds-cluster-param-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.rds-param-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.rds-subnet-group:
```
  filters:
⭐  - config-compliance

```

# 




### aws.redshift:
```
  actions:
⭐  - set-attributes

```

# 




### aws.rest-resource:
```
  filters:
⭐  - config-compliance

```

# 




### aws.rest-vpclink:
```
  filters:
⭐  - config-compliance

```

# 




### aws.route-table:
```
  filters:
⭐  - config-compliance

```

# 




### aws.rrset:
```
  filters:
⭐  - config-compliance

```

# 




### aws.sagemaker-endpoint:
```
  filters:
⭐  - config-compliance

```

# 




### aws.sagemaker-endpoint-config:
```
  filters:
⭐  - config-compliance

```

# 




### aws.sagemaker-model:
```
  filters:
⭐  - config-compliance

```

# 




### aws.sagemaker-notebook:
```
  filters:
⭐  - config-compliance

```

# 




### aws.secrets-manager:
```
  filters:
⭐  - config-compliance

```

# 




### aws.shield-protection:
```
  filters:
⭐  - config-compliance

```

# 




### aws.sns:
```
  filters:
⭐  - config-compliance

```

# 




### aws.sqs:
```
  filters:
⭐  - config-compliance

```

# 




### aws.ssm-parameter:
```
  filters:
⭐  - config-compliance

```

# 




### aws.step-machine:
```
  filters:
⭐  - config-compliance

```

# 




### aws.transit-attachment:
```
  filters:
⭐  - config-compliance

```

# 




### aws.transit-gateway:
```
  filters:
⭐  - config-compliance

```

# 




### aws.user-pool:
```
  filters:
⭐  - config-compliance

```

# 




### aws.vpc-endpoint:
```
  filters:
⭐  - config-compliance

```

# 




### aws.workspaces:
```
  filters:
⭐  - config-compliance

```

# 

