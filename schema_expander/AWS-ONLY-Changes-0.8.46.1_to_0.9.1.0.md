# AWS CUSTODIAN SCHEMA DIFF:

👉👉 *ANY ITEMS WITH ⭐ NEXT TO THEM ARE NEW SINCE LAST RELEASE*

👉👉 *ANY ITEMS WITH ❌ NEXT TO THEM ARE REMOVED SINCE LAST RELEASE*

# 


AWS resources in c7n v0.8.46.1:    **160**

AWS resources in c7n v0.9.1:    **170**
# 


### ⭐ New Items:

    Resources:  10
    Actions:  93
    Filters:  24


### ❌ Removed Items:

    Resources:  0
    Actions:  0
    Filters:  26 


# 





### **New Resources Added In New Schema:**

    ⭐  backup-vault
    ⭐  elasticache-group
    ⭐  emr-security-configuration
    ⭐  glue-catalog
    ⭐  glue-classifier
    ⭐  glue-ml-transform
    ⭐  glue-security-configuration
    ⭐  glue-trigger
    ⭐  glue-workflow
    ⭐  qldb


# 


# Schema:



### aws.account:
```
  actions:
⭐  - set-password-policy

```

# 




### aws.app-elb:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.app-elb-target-group:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.asg:
```
  actions:
⭐  - copy-related-tag

```

# 




 ### ✅ New AWS Resource - aws.backup-vault ✅

### backup-vault:
```
     actions:
⭐   - auto-tag-user
⭐   - copy-related-tag
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - mark-for-op
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - remove-tag
⭐   - tag
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - kms-key
⭐   - marked-for-op
⭐   - ops-item
⭐   - value

```

# 




### aws.cfn:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.cloudhsm-cluster:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.config-recorder:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.datapipeline:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.dax:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.directconnect:
```
  actions:
⭐  - auto-tag-user
⭐  - copy-related-tag
⭐  - mark-for-op
⭐  - remove-tag
⭐  - tag
  filters:
⭐  - marked-for-op

```

# 




### aws.directory:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.distribution:
```
  actions:
⭐  - set-attributes
  filters:
⭐  - distribution-config

```

# 




### aws.dlm-policy:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.dms-endpoint:
```
  actions:
⭐  - auto-tag-user
⭐  - copy-related-tag
⭐  - mark-for-op
⭐  - remove-tag
⭐  - tag
  filters:
⭐  - marked-for-op

```

# 




### aws.dms-instance:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.ec2:
```
  filters:
⭐  - ssm-compliance

```

# 




### aws.ecr:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.ecs:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.ecs-container-instance:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.ecs-service:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.ecs-task:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.ecs-task-definition:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.efs:
```
  actions:
⭐  - configure-lifecycle-policy
  filters:
⭐  - lifecycle-policy

```

# 




### aws.efs-mount-target:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.eks:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.elastic-ip:
```
  filters:
❌  - json-diff

```

# 




 ### ✅ New AWS Resource - aws.elasticache-group ✅

### elasticache-group:
```
     actions:
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - metrics
⭐   - ops-item
⭐   - value

```

# 




### aws.elasticbeanstalk-environment:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.elasticsearch:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.elb:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.emr:
```
  actions:
⭐  - copy-related-tag

```

# 




 ### ✅ New AWS Resource - aws.emr-security-configuration ✅

### emr-security-configuration:
```
     actions:
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - ops-item
⭐   - value

```

# 




### aws.eni:
```
  filters:
❌  - json-diff

```

# 




### aws.event-rule-target:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.fsx:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.fsx-backup:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.gamelift-build:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




 ### ✅ New AWS Resource - aws.glue-catalog ✅

### glue-catalog:
```
     actions:
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - set-encryption
⭐   - webhook
     filters:
⭐   - cross-account
⭐   - event
⭐   - finding
⭐   - glue-security-config
⭐   - ops-item
⭐   - value

```

# 




 ### ✅ New AWS Resource - aws.glue-classifier ✅

### glue-classifier:
```
     actions:
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - ops-item
⭐   - value

```

# 




### aws.glue-crawler:
```
  filters:
⭐  - security-config

```

# 




### aws.glue-dev-endpoint:
```
  filters:
⭐  - security-config
⭐  - subnet

```

# 




### aws.glue-job:
```
  filters:
⭐  - security-config

```

# 




 ### ✅ New AWS Resource - aws.glue-ml-transform ✅

### glue-ml-transform:
```
     actions:
⭐   - auto-tag-user
⭐   - copy-related-tag
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - mark-for-op
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - remove-tag
⭐   - tag
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - marked-for-op
⭐   - ops-item
⭐   - value

```

# 




 ### ✅ New AWS Resource - aws.glue-security-configuration ✅

### glue-security-configuration:
```
     actions:
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - ops-item
⭐   - value

```

# 




 ### ✅ New AWS Resource - aws.glue-trigger ✅

### glue-trigger:
```
     actions:
⭐   - auto-tag-user
⭐   - copy-related-tag
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - mark-for-op
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - remove-tag
⭐   - tag
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - marked-for-op
⭐   - ops-item
⭐   - value

```

# 




 ### ✅ New AWS Resource - aws.glue-workflow ✅

### glue-workflow:
```
     actions:
⭐   - auto-tag-user
⭐   - copy-related-tag
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - mark-for-op
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - remove-tag
⭐   - tag
⭐   - webhook
     filters:
⭐   - event
⭐   - finding
⭐   - marked-for-op
⭐   - ops-item
⭐   - security-config
⭐   - value

```

# 




### aws.iam-role:
```
  actions:
⭐  - copy-related-tag
⭐  - set-boundary

```

# 




### aws.iam-user:
```
  actions:
⭐  - copy-related-tag
⭐  - set-boundary

```

# 




### aws.internet-gateway:
```
  actions:
⭐  - delete
  filters:
❌  - json-diff

```

# 




### aws.kafka:
```
  actions:
⭐  - auto-tag-user
⭐  - copy-related-tag
⭐  - mark-for-op
⭐  - remove-tag
⭐  - set-monitoring
⭐  - tag
  filters:
⭐  - marked-for-op

```

# 




### aws.lambda:
```
  filters:
⭐  - kms-key

```

# 




### aws.message-broker:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.network-acl:
```
  filters:
❌  - json-diff

```

# 




 ### ✅ New AWS Resource - aws.qldb ✅

### qldb:
```
     actions:
⭐   - auto-tag-user
⭐   - copy-related-tag
⭐   - delete
⭐   - invoke-lambda
⭐   - invoke-sfn
⭐   - mark-for-op
⭐   - notify
⭐   - post-finding
⭐   - post-item
⭐   - put-metric
⭐   - remove-tag
⭐   - tag
⭐   - webhook
     filters:
⭐   - config-compliance
⭐   - event
⭐   - finding
⭐   - marked-for-op
⭐   - ops-item
⭐   - value

```

# 




### aws.r53domain:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.rds-cluster-snapshot:
```
  filters:
⭐  - config-compliance
⭐  - cross-account

```

# 




### aws.redshift:
```
  actions:
⭐  - copy-related-tag
⭐  - pause
⭐  - resume
  filters:
⭐  - offhour
⭐  - onhour

```

# 




### aws.rest-account:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.rest-resource:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.rest-vpclink:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.route-table:
```
  filters:
⭐  - vpc

```

# 




### aws.s3:
```
  actions:
⭐  - copy-related-tag
⭐  - set-public-block
⭐  - set-replication
  filters:
⭐  - bucket-logging
⭐  - check-public-block

```

# 




### aws.sagemaker-endpoint:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.sagemaker-endpoint-config:
```
  actions:
⭐  - copy-related-tag
  filters:
⭐  - kms-key

```

# 




### aws.sagemaker-job:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.sagemaker-model:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.sagemaker-notebook:
```
  actions:
⭐  - copy-related-tag
  filters:
⭐  - kms-key

```

# 




### aws.sagemaker-transform-job:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.secrets-manager:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.security-group:
```
  actions:
⭐  - set-permissions
  filters:
❌  - json-diff

```

# 




### aws.shield-attack:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.shield-protection:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.snowball:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.snowball-cluster:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.sns:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.sqs:
```
  actions:
⭐  - modify-policy

```

# 




### aws.ssm-activation:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.step-machine:
```
  actions:
⭐  - copy-related-tag

```

# 




### aws.subnet:
```
  filters:
⭐  - vpc
❌  - json-diff

```

# 




### aws.support-case:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.transit-attachment:
```
  actions:
⭐  - post-finding
  filters:
❌  - finding

```

# 




### aws.vpc:
```
  filters:
❌  - json-diff

```

# 




### aws.vpc-endpoint:
```
  actions:
⭐  - auto-tag-user
⭐  - copy-related-tag
⭐  - mark-for-op
⭐  - normalize-tag
⭐  - remove-tag
⭐  - rename-tag
⭐  - tag
⭐  - tag-trim
  filters:
⭐  - marked-for-op
⭐  - tag-count

```

# 




### aws.vpn-connection:
```
  filters:
❌  - json-diff

```

# 




### aws.vpn-gateway:
```
  filters:
❌  - json-diff

```

# 




### aws.waf:
```
  filters:
❌  - json-diff

```

# 




### aws.waf-regional:
```
  actions:
⭐  - auto-tag-user
⭐  - copy-related-tag
⭐  - mark-for-op
⭐  - remove-tag
⭐  - tag
  filters:
⭐  - marked-for-op
❌  - json-diff

```

# 





