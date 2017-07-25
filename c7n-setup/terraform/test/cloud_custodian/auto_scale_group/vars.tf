variable "name" {
   description = "This is the name of the resource needed for the cloud custodian poller."
   default = "cloud_custodian"
}

variable "reference" {
   description = "Provide an Environment reference"
   default     = "tst"
}

variable "ami_name" {
   description = "This is the ami used to deploy instances in the cluster used for cloud custodian poller."
   default = "<SOME-AMI-NAME-DONT-USE-ID>"
}

variable "ami_owner_account" {
   description = "This is the owner account number for the account that owns the ami."
   default = "<ACCOUNT-NUMBER-HERE>"
}

variable "instance_size" {
   description = "This is the size of the instance that is being created."
   default = "t2.micro"
}

variable "root_volume_size" {
   description = "The size of the root volume in GB.  Cannot be less that AMI size currently 50GB."
   default = "50"
}

variable "iam_role" {
  description = "provide an IAM role"
  default     = "<IAM-INSTANCE-ROLE-NAME-DONT-USE-ARN-JUST-NAME>"
}

variable "ec2_keypair" {
   description = "This is the EC2 Key Pair for remote access to the provisioned instances"
   default = "cloud-operations"
}

variable "ec2_security_groups" {
   description = "This is the list of EC2 security groups."
   default = ["<SECURITY-GROUP-ID-HERE>", "<SECURITY-GROUP-ID-HERE>"]
}

variable "ebs_optimized" {
   description = "Should we use EBS optimized storage"
   default = false
}

variable "worker_count_min" {
   description = "Minimum servers do you need"
   default = 0
}

variable "worker_count_max" {
   description = "Maximum servers do you need"
   default = 10
}

variable "health_check_grace_period" {
   description = "How long is the grace period to wait for the server boot before health checks fail"
   default = 300
}

variable vpc_zone_identifier {
   description = "What VPC Zones should be used"
   default = ["<SUBNET-ID-HERE>", "<SUBNET-ID-HERE>", "<SUBNET-ID-HERE>"]
}

variable "backup" {
   description = "Provide a name"
   default     = "NONE"
}

variable "billing_cost_center" {
   description = "Provide a cost center for billing reporting"
   default     = "NONE"
}

variable "environment" {
   description = "Provide an enviroment tag dev/prod/test/etc"
   default     = "test"
}

variable "resource_contact" {
   description = "Provide an email"
   default     = "<EMAIL-ADDRESS-HERE>"
}

variable "resource_purpose" {
   description = "Provide a description of what your using this for"
   default     = "Cloud Custodian"
}

variable "s3_custodian_log_bucket" {
   description = "The S3 bucket used to store the Cloud Custodian logs"
   default     = "cloud-custodian"
}

variable "custodian_queue" {
   description = "The URL of the SQS Queue used for Cloud Custodian"
}

variable "custodian_queue_name" {
   description = "The name of the SQS Queue used for Cloud Custodian"
}