
  # **Cloud Custodian CloudTrail Event Triggers**

  
  
  *List Created By: Jamison Roberts May 1st 2020*
  * Cloud Custodian Does Have Some Built In Event [Shortcuts](https://github.com/cloud-custodian/cloud-custodian/blob/master/c7n/cwe.py#L28-L69)




## **ACCOUNT:**

    - source: signin.amazonaws.com
      event: ConsoleLogin
      ids: "userIdentity.arn"
* [ConsoleLogin Example Policy - Detect And Notify On Root Console Logins](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/ConsoleLogin.yaml)


## **ACM - AWS Certificate Manager:**

    - source: acm.amazonaws.com
      event: ImportCertificate
      ids: "responseElements.certificateArn"

    - source: acm.amazonaws.com
      event: RequestCertificate
      ids: "responseElements.certificateArn"
* [ImportCertificate and RequestCertificate Example Policy - Detect And Delete Insecure Certs](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/ImportRequestCertificate.yaml)


## **ALB - Application Load Balancers:**

    - source: "elasticloadbalancing.amazonaws.com"
      event: CreateListener
      ids: "requestParameters.loadBalancerArn"
      
    - source: elasticloadbalancing.amazonaws.com
      event: CreateLoadBalancer
      ids: "responseElements.loadBalancers[].loadBalancerArn"

    - source: "elasticloadbalancing.amazonaws.com"
      event: ModifyListener
      ids: "responseElements.listeners[].loadBalancerArn"      
      
* [CreateLoadBalancer, CreateListener, ModifyListener Example Policy - Update ALBs To TLS1.2](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateLoadBalancerCreateModifyListener.yaml)      
      
## **AMI - Amazon Machine Image:**

    - source: ec2.amazonaws.com
      event: CopyImage
      ids: "responseElements.imageId"

    - source: "ec2.amazonaws.com"
      event: CreateImage
      ids: "responseElements.imageId"

    - source: "ec2.amazonaws.com"
      event: ModifyImageAttribute
      ids: "requestParameters.imageId"

* [ModifyImageAttribute Example Policy - Detect And Remediate Public AMI](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/ModifyImageAttribute.yaml)

## **APIGATEWAY - Rest API:**

    - source: apigateway.amazonaws.com
      event: CreateRestApi
      ids: 'responseElements.restapiUpdate.restApiId'



## **ASG - EC2 Autoscaling Group:**

    - source: autoscaling.amazonaws.com
      event: CreateAutoScalingGroup
      ids: requestParameters.autoScalingGroupName



## **EBS - Elastic Block Storage:**

    - source: "ec2.amazonaws.com"
      event: ModifySnapshotAttribute
      ids: "requestParameters.snapshotId"    

* [ModifySnapshotAttribute Example Policy - Detect Public Snapshots](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/ModifySnapshotAttribute.yaml)



## **CFN - CloudFormation Templates/Stacks:**

    - source: cloudformation.amazonaws.com
      event: CreateStack
      ids: "responseElements.stackId"



## **CLOUDFRONT - Distribution:**

    - source: cloudfront.amazonaws.com
      event: CreateDistribution
      ids: "responseElements.distribution.id"

    - source: cloudfront.amazonaws.com
      event: UpdateDistribution
      ids: "responseElements.distribution.id"  

* [CreateDistribution, UpdateDistribution Example Policy - Remove Allow-All Access](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateUpdateDistribution.yaml)

## **CLOUDWATCH - Logs**

    - source: "logs.amazonaws.com"
      event: CreateLogGroup
      ids: "requestParameters.logGroupName"

    - source: "logs.amazonaws.com"
      event: DisassociateKmsKey
      ids: "requestParameters.logGroupName"



## **CODEBUILD - Project:**

    - source: codebuild.amazonaws.com
      event: CreateNetworkInterface
      ids: "requestParameters.groupSet.items[].groupId"

    - source: codebuild.amazonaws.com
      event: CreateProject
      ids: "responseElements.project.name"



## **COGNITO - Identity Pool:**

    - source: cognito-identity.amazonaws.com
      event: CreateIdentityPool
      ids: "responseElements.identityPoolId"

* [CreateIdentityPool Example Policy - Delete Anonymous Access Identity Pools](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateIdentityPool.yaml)

## **DATAPIPELINE - Pipeline:**

    - source: datapipeline.amazonaws.com
      event: CreatePipeline
      ids: "responseElements.pipelineId"



## **DMS - Database Migration Service:**

    - source: "dms.amazonaws.com"
      event: CreateReplicationInstance
      ids: "requestParameters.replicationInstanceIdentifier"

    - source: dms.amazonaws.com
      event: CreateEndpoint
      ids: "responseElements.endpoint.endpointArn"

    - source: dms.amazonaws.com
      event: ModifyEndpoint
      ids: "responseElements.endpoint.endpointArn"

* [CreateReplicationInstance Example Policy - Terminate Public DMS Instances](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateReplicationInstance.yaml)

* [CreateEndpoint, ModifyEndpoint Example Policies - Ensure SSL Is Used On Endpoints](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateModifyEndpoint.yaml)

## **EC2 - Elastic Cloud Compute:**

    - source: ec2.amazonaws.com
      event: StartInstances
      ids: "responseElements.instancesSet.items[].instanceId"

    - source: ec2.amazonaws.com
      event: StopInstances
      ids: "responseElements.instancesSet.items[].instanceId"

    - source: ec2.amazonaws.com
      event: TerminateInstances
      ids: "responseElements.instancesSet.items[].instanceId"      
    
    - source: ec2.amazonaws.com
      event: CreateNetworkInterface
      ids: "requestParameters.groupSet.items[].groupId"



## **ECS - Elastic Container Service:**

    - source: ecs.amazonaws.com
      event: CreateService
      ids: 'responseElements.service.serviceArn'

    - source: ecs.amazonaws.com
      event: RunTask
      ids: 'responseElements.tasks[].taskArn'



## **EFS - Elastic File System:**

    - source: elasticfilesystem.amazonaws.com
      event: CreateFileSystem
      ids: "responseElements.fileSystemId"

* [CreateFileSystem Example Policy - Delete Unencrypted EFS](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateFileSystem.yaml)

## **EKS - Elastic Kubernetes Service:**

    - source: eks.amazonaws.com
      event: CreateCluster
      ids: "requestParameters.name"



## **ELB - Elastic Load Balancers (Classic):**

    - source: "elasticloadbalancing.amazonaws.com"
      event: CreateLoadBalancerListeners
      ids: "requestParameters.loadBalancerName"

    - source: "elasticloadbalancing.amazonaws.com"
      event: CreateLoadBalancerPolicy
      ids: "requestParameters.loadBalancerName"     

    - source: elasticloadbalancing.amazonaws.com
      event: CreateTargetGroup
      ids: "responseElements.targetGroups[].targetGroupArn"

    - source: elasticloadbalancing.amazonaws.com
      event: RegisterInstancesWithLoadBalancer
      ids: "requestParameters.loadBalancerName"

* [CreateLoadBalancerListeners, RegisterInstancesWithLoadBalancer Example Policy - Delete Non-SSL ELBs](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/CreateLoadBalancerListenersRegisterInstancesWithLoadBalancer.yaml)
* [CreateLoadBalancer, Example Policy - Update To TLS1.2](https://github.com/jtroberts83/Cloud-Custodian/blob/master/Policies/ELBCreateLoadBalancerCreateModifyListener.yaml)

## **EMR - Elastic Map Reduce:**

    - source: elasticmapreduce.amazonaws.com
      event: RunJobFlow
      ids: "responseElements.jobFlowId"



## **ES - Elasticsearch Service:**

    - source: es.amazonaws.com
      event: CreateElasticsearchDomain
      ids: "requestParameters.domainName"



## **IAM - Identity Access Manager:**

    - source: "iam.amazonaws.com"
      event: CreateUser
      ids: "requestParameters.userName"

    - source: iam.amazonaws.com
      event: AttachRolePolicy
      ids: "requestParameters.roleName"

    - source: iam.amazonaws.com
      event: CreatePolicy
      ids: "responseElements.policy.policyId"

    - source: iam.amazonaws.com
      event: CreatePolicyVersion
      ids: "requestParameters.policyArn"
      
   

## **KINESIS - Data Streams:**

    - source: "kinesis.amazonaws.com"
      event: "CreateStream"
      ids: "requestParameters.streamName"
      


## **KINESIS - Firehose:**

    - source: "firehose.amazonaws.com"
      event: "CreateDeliveryStream"
      ids: "requestParameters.deliveryStreamName"



## **KMS - Key Management Service:**

    - source: kms.amazonaws.com
      event: CreateKey
      ids: "responseElements.keyMetadata.arn"



## **LAMBDA - Serverless Functions:**

    - source: lambda.amazonaws.com
      event: AddPermission20150331
      ids: "requestParameters.functionName"

    - source: lambda.amazonaws.com
      event: AddPermission20150331v2
      ids: "requestParameters.functionName"

    - source: lambda.amazonaws.com
      event: CreateFunction20150331
      ids: "requestParameters.functionName"

    - source: lambda.amazonaws.com
      event: UpdateFunctionConfiguration20150331v2
      ids: "requestParameters.functionName"



## **MQ - Message Broker:**

    - source: amazonmq.amazonaws.com
      event: CreateBroker
      ids: "responseElements.brokerId"



## **RDS - Relational Database Service:**

    - source: rds.amazonaws.com
      event: CreateDBCluster
      ids: "requestParameters.dBClusterIdentifier"

    - source: rds.amazonaws.com
      event: CreateDBInstance
      ids: "requestParameters.dBInstanceIdentifier"



## **REDSHIFT - Clusters:**

    - source: redshift.amazonaws.com
      event: CreateCluster
      ids: 'responseElements.clusterIdentifier'



## **S3 - Simple Storage Service (Blob storage):**

    - source: s3.amazonaws.com
      event: CopyObject
      ids: 'requestParameters.bucketName'

    - source: 's3.amazonaws.com'
      event: PutBucketAcl
      ids: "requestParameters.bucketName"

    - source: 's3.amazonaws.com'
      event: PutBucketPolicy
      ids: "requestParameters.bucketName"



## **SAGEMAKER - Notebooks:**

    - source: sagemaker.amazonaws.com
      event: CreateNotebookInstance
      ids: "responseElements.notebookInstanceArn"



## **SECURITY-GROUP:**

    - source: ec2.amazonaws.com
      event: AuthorizeSecurityGroupEgress
      ids: "requestParameters.groupId"

    - source: ec2.amazonaws.com
      event: AuthorizeSecurityGroupIngress
      ids: "requestParameters.groupId"
    
    - source: ec2.amazonaws.com
      event: CreateSecurityGroup
      ids: "responseElements.groupId"

    - source: ec2.amazonaws.com
      event: RevokeSecurityGroupEgress
      ids: "requestParameters.groupId"

    - source: ec2.amazonaws.com
      event: RevokeSecurityGroupIngress
      ids: "requestParameters.groupId"
      
      

## **SNS - Simple Notification Service:**

    - source: sns.amazonaws.com
      event: CreateTopic
      ids: 'responseElements.topicArn'

    - source: sns.amazonaws.com
      event: SetTopicAttributes
      ids: 'requestParameters.topicArn' 



## **SQS - Simple Queue Service:**

    - source: sqs.amazonaws.com
      event: CreateQueue
      ids: 'responseElements.queueUrl'

    - source: sqs.amazonaws.com
      event: SetQueueAttributes
      ids: 'requestParameters.queueUrl'

    - source: sqs.amazonaws.com
      event: TagQueue
      ids: 'requestParameters.queueUrl'

    - source: sqs.amazonaws.com
      event: UntagQueue
      ids: 'requestParameters.queueUrl'



## **SUBNET:**

    - source: ec2.amazonaws.com
      event: CreateSubnet
      ids: "responseElements.subnet.subnetId"

    - source: ec2.amazonaws.com
      event: ModifySubnetAttribute
      ids: "requestParameters.subnetId"      
      


## **VPC:**

    - source: ec2.amazonaws.com
      event: CreateVpcPeeringConnection
      ids: 'responseElements.vpcPeeringConnection.vpcPeeringConnectionId'

