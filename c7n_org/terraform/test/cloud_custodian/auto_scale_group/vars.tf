variable "name" {
   description = "This is the name of the resource needed for the cloud custodian poller."
   default = "Cloud-Custodian-Org-Runner"
}

variable "reference" {
   description = "Provide an Environment reference"
   default     = "PRD"
}

variable "ami_name" {
   description = "This is the ami used to deploy instances in the cluster used for cloud custodian poller."
   default = "<YOUR_AMI_NAMING_PREFIX>*"
}

variable "ami_owner_account" {
   description = "This is the owner account number for the account that owns the ami."
   default = "<ACCOUNT_NUMBER"
}

variable "instance_size" {
   description = "This is the size of the instance that is being created."
   default = "c4.4xlarge"
}

variable "root_volume_size" {
   description = "The size of the root volume in GB.  Cannot be less that AMI size currently 50GB."
   default = "120"
}

variable "iam_role" {
  description = "provide an IAM role"
  default     = "<IAM_INSTANCE_PROFILE>"
}

variable "ec2_keypair" {
   description = "This is the EC2 Key Pair for remote access to the provisioned instances"
   default = "<KEY_PAIR_NAME>"
}

variable "ec2_security_groups" {
   description = "This is the list of EC2 security groups."
   default = ["sg-XXXXXXXX", "sg-XXXXXXXXXX"]
}

variable "ebs_optimized" {
   description = "Should we use EBS optimized storage"
   default = true
}

variable "worker_count_min" {
   description = "Minimum servers do you need"
   default = 0
}

variable "worker_count_max" {
   description = "Maximum servers do you need"
   default = 0
}

variable "health_check_grace_period" {
   description = "How long is the grace period to wait for the server boot before health checks fail"
   default = 300
}

variable vpc_zone_identifier {
   description = "What VPC Zones should be used"
   default = ["subnet-XXXXXXXX", "subnet-XXXXXXXXX", "subnet-XXXXXXXXXX"]
}

variable "backup" {
   description = "Provide a name"
   default     = "NONE"
}

variable "billing_cost_center" {
   description = "Provide a cost center for billing reporting"
   default     = "<COST_CENTER_CODE>"
}

variable "environment" {
   description = "Provide an enviroment tag dev/prod/test/etc"
   default     = "PRD"
}

variable "resource_contact" {
   description = "Provide an email"
   default     = "<CUSTODIAN_EMAIL_ADDRESS>"
}

variable "resource_purpose" {
   description = "Provide a description of what your using this for"
   default     = "Spins up daily to run Cloud Custodian Org Runner against all accounts"
}
