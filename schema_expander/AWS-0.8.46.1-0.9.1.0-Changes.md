# AWS CUSTODIAN SCHEMA DIFF:

👉👉 *Any Items With A ⭐ Next To Them Are NEW Since Last Release*

👉👉 *Any Items With A ❌ Next To Them Are REMOVED Since Last Release*

# 


AWS resources in c7n v0.8.46.1:    **160**

AWS resources in c7n v0.9.1:    **170**
# 


### ⭐ New Items:

    Resources:  10
    Actions:  93
    Filters:  26


### ❌ Removed Items:

    Resources:  0
    Actions:  0
    Filters:  28 


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
    - enable-cloudtrail
    - enable-data-events
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - request-limit-increase
    - set-ebs-encryption
    - set-s3-public-block
    - set-shield-advanced
    - set-xray-encrypt
    - webhook
  filters:
    - check-cloudtrail
    - check-config
    - credential
    - default-ebs-encryption
    - event
    - finding
    - glue-security-config
    - guard-duty
    - has-virtual-mfa
    - iam-summary
    - missing
    - ops-item
    - password-policy
    - s3-public-block
    - service-limit
    - shield-enabled
    - value
    - xray-encrypt-key

```

# 




### aws.acm-certificate:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - health-event
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.alarm:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.ami:
```
  actions:
    - auto-tag-user
    - copy
    - copy-related-tag
    - deregister
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-launch-permissions
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - image-age
    - marked-for-op
    - ops-item
    - tag-count
    - unused
    - value

```

# 




### aws.app-elb:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-listener
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-s3-logging
    - set-shield
    - set-waf
    - tag
    - webhook
  filters:
    - config-compliance
    - default-vpc
    - event
    - finding
    - health-event
    - healthcheck-protocol-mismatch
    - is-logging
    - is-not-logging
    - listener
    - marked-for-op
    - metrics
    - network-location
    - ops-item
    - security-group
    - shield-enabled
    - subnet
    - tag-count
    - target-group
    - value
    - vpc
    - waf-enabled

```

# 




### aws.app-elb-target-group:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - default-vpc
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.asg:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - propagate-tags
    - put-metric
    - remove-tag
    - rename-tag
    - resize
    - resume
    - suspend
    - tag
    - tag-trim
    - webhook
  filters:
    - capacity-delta
    - config-compliance
    - event
    - finding
    - image
    - image-age
    - invalid
    - launch-config
    - marked-for-op
    - metrics
    - network-location
    - not-encrypted
    - offhour
    - onhour
    - ops-item
    - progagated-tags
    - security-group
    - subnet
    - tag-count
    - user-data
    - valid
    - value
    - vpc-id

```

# 




### aws.backup-plan:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

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




### aws.batch-compute:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - update-environment
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - security-group
    - subnet
    - value

```

# 




### aws.batch-definition:
```
  actions:
    - deregister
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.cache-cluster:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - snapshot
    - tag
    - webhook
  filters:
    - event
    - finding
    - health-event
    - marked-for-op
    - metrics
    - network-location
    - ops-item
    - security-group
    - subnet
    - tag-count
    - value

```

# 




### aws.cache-snapshot:
```
  actions:
    - auto-tag-user
    - copy-cluster-tags
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - age
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.cache-subnet-group:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.cfn:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-protection
    - tag
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.cloud-directory:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.cloudhsm-cluster:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.cloudsearch:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.cloudtrail:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-logging
    - tag
    - update-trail
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - is-shadow
    - marked-for-op
    - ops-item
    - status
    - value

```

# 




### aws.codebuild:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.codecommit:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.codepipeline:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.config-recorder:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.config-rule:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - status
    - value

```

# 




### aws.customer-gateway:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.datapipeline:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.dax:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - update-cluster
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - security-group
    - subnet
    - value

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
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
⭐  - marked-for-op
    - event
    - finding
    - health-event
    - ops-item
    - value

```

# 




### aws.directory:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - health-event
    - ops-item
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.distribution:
```
  actions:
⭐  - set-attributes
    - auto-tag-user
    - copy-related-tag
    - disable
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-protocols
    - set-shield
    - set-waf
    - tag
    - webhook
  filters:
⭐  - distribution-config
    - config-compliance
    - event
    - finding
    - marked-for-op
    - metrics
    - mismatch-s3-origin
    - ops-item
    - shield-enabled
    - shield-metrics
    - tag-count
    - value
    - waf-enabled

```

# 




### aws.dlm-policy:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

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
    - delete
    - invoke-lambda
    - invoke-sfn
    - modify-endpoint
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
⭐  - marked-for-op
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.dms-instance:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-instance
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - health-event
    - kms-key
    - marked-for-op
    - ops-item
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.dynamodb-backup:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.dynamodb-stream:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.dynamodb-table:
```
  actions:
    - auto-tag-user
    - backup
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-stream
    - tag
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - health-event
    - kms-key
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.ebs:
```
  actions:
    - auto-tag-user
    - copy-instance-tags
    - copy-related-tag
    - delete
    - detach
    - encrypt-instance-volumes
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - snapshot
    - tag
    - tag-trim
    - webhook
  filters:
    - config-compliance
    - event
    - fault-tolerant
    - finding
    - health-event
    - instance
    - kms-alias
    - marked-for-op
    - metrics
    - modifyable
    - ops-item
    - tag-count
    - value

```

# 




### aws.ebs-snapshot:
```
  actions:
    - auto-tag-user
    - copy
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - age
    - cross-account
    - event
    - finding
    - marked-for-op
    - ops-item
    - skip-ami-snapshots
    - tag-count
    - unused
    - value

```

# 




### aws.ec2:
```
  actions:
    - auto-tag-user
    - autorecover-alarm
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - propagate-spot-tags
    - put-metric
    - reboot
    - remove-tag
    - rename-tag
    - resize
    - send-command
    - set-instance-profile
    - set-monitoring
    - snapshot
    - start
    - stop
    - tag
    - tag-trim
    - terminate
    - webhook
  filters:
⭐  - ssm-compliance
    - check-permissions
    - config-compliance
    - default-vpc
    - ebs
    - ephemeral
    - event
    - finding
    - health-event
    - image
    - image-age
    - instance-age
    - instance-attribute
    - instance-uptime
    - marked-for-op
    - metrics
    - network-location
    - offhour
    - onhour
    - ops-item
    - security-group
    - singleton
    - ssm
    - state-age
    - subnet
    - tag-count
    - termination-protected
    - user-data
    - value
    - vpc

```

# 




### aws.ec2-reserved:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.ecr:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - set-immutability
    - set-lifecycle
    - set-scanning
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - lifecycle-rule
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.ecs:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.ecs-container-instance:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-state
    - tag
    - update-agent
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - taggable
    - value

```

# 




### aws.ecs-service:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - taggable
    - task-definition
    - value

```

# 




### aws.ecs-task:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - stop
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - taggable
    - task-definition
    - value

```

# 




### aws.ecs-task-definition:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.efs:
```
  actions:
⭐  - configure-lifecycle-policy
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
⭐  - lifecycle-policy
    - event
    - finding
    - health-event
    - kms-key
    - marked-for-op
    - metrics
    - ops-item
    - tag-count
    - value

```

# 




### aws.efs-mount-target:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - security-group
    - subnet
    - value

```

# 




### aws.eks:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - update-config
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.elastic-ip:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - release
    - remove-tag
    - rename-tag
    - set-shield
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - shield-enabled
    - tag-count
    - value

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




### aws.elasticbeanstalk:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.elasticbeanstalk-environment:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - terminate
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.elasticsearch:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.elb:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - disable-s3-logging
    - enable-s3-logging
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-shield
    - set-ssl-listener-policy
    - tag
    - webhook
  filters:
    - config-compliance
    - default-vpc
    - event
    - finding
    - health-event
    - healthcheck-protocol-mismatch
    - instance
    - is-logging
    - is-not-logging
    - is-ssl
    - marked-for-op
    - metrics
    - network-location
    - ops-item
    - security-group
    - shield-enabled
    - shield-metrics
    - ssl-policy
    - subnet
    - tag-count
    - value
    - vpc

```

# 




### aws.emr:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - terminate
    - webhook
  filters:
    - event
    - finding
    - health-event
    - marked-for-op
    - metrics
    - ops-item
    - value

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
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - set-flow-log
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - flow-logs
    - marked-for-op
    - network-location
    - ops-item
    - security-group
    - subnet
    - tag-count
    - value
    - vpc

```

# 




### aws.event-rule:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.event-rule-target:
```
  actions:
⭐  - post-finding
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - cross-account
    - event
    - ops-item
    - value

```

# 




### aws.firehose:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - encrypt-s3-destination
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.fsx:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - backup
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - update
    - webhook
  filters:
    - event
    - finding
    - kms-key
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.fsx-backup:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - kms-key
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.gamelift-build:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.gamelift-fleet:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.glacier:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

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




### aws.glue-connection:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - security-group
    - subnet
    - value

```

# 




### aws.glue-crawler:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
⭐  - security-config
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.glue-database:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.glue-dev-endpoint:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
⭐  - security-config
⭐  - subnet
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.glue-job:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
⭐  - security-config
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

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




### aws.glue-table:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

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




### aws.health-event:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.healthcheck:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.hostedzone:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-query-logging
    - set-shield
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - query-logging-enabled
    - shield-enabled
    - tag-count
    - value

```

# 




### aws.hsm:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.hsm-client:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.hsm-hapg:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.iam-certificate:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.iam-group:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - check-permissions
    - config-compliance
    - event
    - finding
    - has-inline-policy
    - has-users
    - ops-item
    - usage
    - value

```

# 




### aws.iam-policy:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - check-permissions
    - config-compliance
    - event
    - finding
    - has-allow-all
    - ops-item
    - unused
    - usage
    - used
    - value

```

# 




### aws.iam-profile:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - unused
    - used
    - value

```

# 




### aws.iam-role:
```
  actions:
⭐  - copy-related-tag
⭐  - set-boundary
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - set-policy
    - tag
    - webhook
  filters:
    - check-permissions
    - config-compliance
    - cross-account
    - event
    - finding
    - has-inline-policy
    - has-specific-managed-policy
    - no-specific-managed-policy
    - ops-item
    - unused
    - usage
    - used
    - value

```

# 




### aws.iam-user:
```
  actions:
⭐  - copy-related-tag
⭐  - set-boundary
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-keys
    - remove-tag
    - set-groups
    - tag
    - webhook
  filters:
    - access-key
    - check-permissions
    - config-compliance
    - credential
    - event
    - finding
    - group
    - has-inline-policy
    - marked-for-op
    - mfa-device
    - ops-item
    - policy
    - usage
    - value

```

# 




### aws.identity-pool:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.internet-gateway:
```
  actions:
⭐  - delete
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.iot:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

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
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
⭐  - marked-for-op
    - event
    - finding
    - ops-item
    - security-group
    - subnet
    - value

```

# 




### aws.key-pair:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.kinesis:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - encrypt
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - tag-count
    - value

```

# 




### aws.kinesis-analytics:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.kms:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - grant-count
    - ops-item
    - value

```

# 




### aws.kms-key:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - set-rotation
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - key-rotation-status
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.lambda:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - set-concurrency
    - tag
    - webhook
  filters:
⭐  - kms-key
    - check-permissions
    - config-compliance
    - cross-account
    - event
    - event-source
    - finding
    - marked-for-op
    - metrics
    - network-location
    - ops-item
    - reserved-concurrency
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.lambda-layer:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.launch-config:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - age
    - config-compliance
    - event
    - finding
    - ops-item
    - unused
    - value

```

# 




### aws.launch-template-version:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.lightsail-db:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.lightsail-elb:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.lightsail-instance:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.log-group:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - retention
    - set-encryption
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - last-write
    - marked-for-op
    - metrics
    - ops-item
    - tag-count
    - value

```

# 




### aws.message-broker:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - security-group
    - subnet
    - value

```

# 




### aws.ml-model:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.nat-gateway:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.network-acl:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - s3-cidr
    - subnet
    - tag-count
    - value

```

# 




### aws.ops-item:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - update
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.opswork-cm:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.opswork-stack:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - stop
    - webhook
  filters:
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.peering-connection:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - marked-for-op
    - missing-route
    - ops-item
    - tag-count
    - value

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
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.rds:
```
  actions:
    - auto-patch
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-db
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - resize
    - retention
    - set-public-access
    - set-snapshot-copy-tags
    - snapshot
    - start
    - stop
    - tag
    - tag-trim
    - upgrade
    - webhook
  filters:
    - config-compliance
    - db-parameter
    - default-vpc
    - event
    - finding
    - health-event
    - kms-alias
    - marked-for-op
    - metrics
    - network-location
    - offhour
    - onhour
    - ops-item
    - security-group
    - subnet
    - tag-count
    - upgrade-available
    - value
    - vpc

```

# 




### aws.rds-cluster:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-db-cluster
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - retention
    - snapshot
    - start
    - stop
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - metrics
    - network-location
    - offhour
    - onhour
    - ops-item
    - security-group
    - subnet
    - tag-count
    - value

```

# 




### aws.rds-cluster-param-group:
```
  actions:
    - copy
    - delete
    - invoke-lambda
    - invoke-sfn
    - modify
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.rds-cluster-snapshot:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
⭐  - config-compliance
⭐  - cross-account
    - age
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.rds-param-group:
```
  actions:
    - copy
    - delete
    - invoke-lambda
    - invoke-sfn
    - modify
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.rds-reserved:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.rds-snapshot:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - region-copy
    - remove-tag
    - restore
    - tag
    - webhook
  filters:
    - age
    - config-compliance
    - cross-account
    - event
    - finding
    - latest
    - marked-for-op
    - onhour
    - ops-item
    - tag-count
    - value

```

# 




### aws.rds-subnet-group:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - unused
    - value

```

# 




### aws.rds-subscription:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.redshift:
```
  actions:
⭐  - copy-related-tag
⭐  - pause
⭐  - resume
    - auto-tag-user
    - delete
    - enable-vpc-routing
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-security-groups
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - retention
    - set-logging
    - set-public-access
    - snapshot
    - tag
    - tag-trim
    - webhook
  filters:
⭐  - offhour
⭐  - onhour
    - config-compliance
    - default-vpc
    - event
    - finding
    - kms-key
    - logging
    - marked-for-op
    - metrics
    - network-location
    - ops-item
    - param
    - security-group
    - subnet
    - value

```

# 




### aws.redshift-snapshot:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - revoke-access
    - tag
    - webhook
  filters:
    - age
    - config-compliance
    - cross-account
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.redshift-subnet-group:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.rest-account:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - update
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.rest-api:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - update
    - webhook
  filters:
    - config-compliance
    - cross-account
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.rest-resource:
```
  actions:
⭐  - post-finding
    - delete-integration
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - update-integration
    - update-method
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - rest-integration
    - rest-method
    - value

```

# 




### aws.rest-stage:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - update
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.rest-vpclink:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.route-table:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
⭐  - value
⭐  - vpc
❌  - value
    - event
    - finding
    - marked-for-op
    - ops-item
    - route
    - subnet
    - tag-count

```

# 




### aws.rrset:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.s3:
```
  actions:
⭐  - copy-related-tag
⭐  - set-public-block
⭐  - set-replication
    - attach-encrypt
    - auto-tag-user
    - configure-lifecycle
    - delete
    - delete-bucket-notification
    - delete-global-grants
    - encrypt-keys
    - encryption-policy
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - no-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - remove-website-hosting
    - set-bucket-encryption
    - set-inventory
    - set-statements
    - tag
    - toggle-logging
    - toggle-versioning
    - webhook
  filters:
⭐  - bucket-logging
⭐  - check-public-block
    - bucket-encryption
    - bucket-notification
    - config-compliance
    - cross-account
    - data-events
    - event
    - finding
    - global-grants
    - has-statement
    - inventory
    - is-log-target
    - marked-for-op
    - metrics
    - missing-policy-statement
    - no-encryption-statement
    - ops-item
    - value

```

# 




### aws.sagemaker-endpoint:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.sagemaker-endpoint-config:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
⭐  - kms-key
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.sagemaker-job:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - stop
    - tag
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.sagemaker-model:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.sagemaker-notebook:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - start
    - stop
    - tag
    - webhook
  filters:
⭐  - kms-key
    - event
    - finding
    - marked-for-op
    - ops-item
    - security-group
    - subnet
    - value

```

# 




### aws.sagemaker-transform-job:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - stop
    - tag
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.secrets-manager:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - marked-for-op
    - ops-item
    - value

```

# 




### aws.security-group:
```
  actions:
⭐  - set-permissions
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - patch
    - post-finding
    - post-item
    - put-metric
    - remove-permissions
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - default-vpc
    - diff
    - egress
    - event
    - finding
    - ingress
    - marked-for-op
    - ops-item
    - stale
    - tag-count
    - unused
    - used
    - value

```

# 




### aws.shield-attack:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.shield-protection:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.simpledb:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.snowball:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.snowball-cluster:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.sns:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - modify-policy
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - set-encryption
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - kms-key
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.sqs:
```
  actions:
⭐  - modify-policy
    - auto-tag-user
    - copy-related-tag
    - delete
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-statements
    - remove-tag
    - set-encryption
    - set-retention-period
    - tag
    - webhook
  filters:
    - cross-account
    - event
    - finding
    - kms-key
    - marked-for-op
    - metrics
    - ops-item
    - value

```

# 




### aws.ssm-activation:
```
  actions:
⭐  - post-finding
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.ssm-managed-instance:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - send-command
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.ssm-parameter:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.step-machine:
```
  actions:
⭐  - copy-related-tag
    - auto-tag-user
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.storage-gateway:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - health-event
    - ops-item
    - value

```

# 




### aws.streaming-distribution:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - disable
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - config-compliance
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - tag-count
    - value

```

# 




### aws.subnet:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - set-flow-log
    - tag
    - tag-trim
    - webhook
  filters:
⭐  - value
⭐  - vpc
❌  - json-diff
❌  - value
    - config-compliance
    - event
    - finding
    - flow-logs
    - marked-for-op
    - ops-item
    - tag-count

```

# 




### aws.support-case:
```
  actions:
⭐  - post-finding
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-item
    - put-metric
    - webhook
  filters:
❌  - finding
    - event
    - ops-item
    - value

```

# 




### aws.transit-attachment:
```
  actions:
⭐  - post-finding
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
❌  - finding
    - event
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.transit-gateway:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.user-pool:
```
  actions:
    - delete
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
    - event
    - finding
    - ops-item
    - value

```

# 




### aws.vpc:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - set-flow-log
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - dhcp-options
    - event
    - finding
    - flow-logs
    - internet-gateway
    - marked-for-op
    - nat-gateway
    - ops-item
    - security-group
    - subnet
    - tag-count
    - value
    - vpc-attributes

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
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
⭐  - marked-for-op
⭐  - tag-count
    - cross-account
    - event
    - finding
    - ops-item
    - security-group
    - subnet
    - value
    - vpc

```

# 




### aws.vpn-connection:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.vpn-gateway:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - normalize-tag
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - rename-tag
    - tag
    - tag-trim
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - marked-for-op
    - ops-item
    - tag-count
    - value

```

# 




### aws.waf:
```
  actions:
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
❌  - json-diff
    - config-compliance
    - event
    - finding
    - metrics
    - ops-item
    - value

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
    - invoke-lambda
    - invoke-sfn
    - notify
    - post-finding
    - post-item
    - put-metric
    - webhook
  filters:
⭐  - marked-for-op
❌  - json-diff
    - config-compliance
    - event
    - finding
    - metrics
    - ops-item
    - value

```

# 




### aws.workspaces:
```
  actions:
    - auto-tag-user
    - copy-related-tag
    - invoke-lambda
    - invoke-sfn
    - mark-for-op
    - notify
    - post-finding
    - post-item
    - put-metric
    - remove-tag
    - tag
    - webhook
  filters:
    - connection-status
    - event
    - finding
    - marked-for-op
    - metrics
    - ops-item
    - tag-count
    - value

```

# 

