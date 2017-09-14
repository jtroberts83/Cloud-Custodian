variable "instance_count" {
  description = "How many servers do you need"
  default     = 1
}

variable "name" {
   description = "This is the name of the server resource."
}

variable "reference" {
   description = "Provide an Environment reference.  tst or prd"
}

variable "ami_name" {
   description = "This is the ami used to deploy EC2 instances."
}

variable "ami_owner_account" {
   description = "This is the owner account number for the account that owns the ami."
   default = "<ACCOUNT_NUMBER>"
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
  default     = "<IAM_INSTANCE_ROLE>"
}

variable "ec2_keypair" {
   description = "This is the EC2 Key Pair for remote access to the provisioned instances"
   default = "<KEY_PAIR_NAME>"
}

variable "vpc_security_groups" {
   type = "list"
   description = "This is the list of VPC security groups."
}

variable "ebs_optimized" {
   description = "Should we use EBS optimized storage"
   default = true
}

variable "monitoring" {
   description = "Should server resource be monitored"
   default = true
}

variable "subnet_id" {
   description = "Provide subnet to use."
}

variable "user_data" {
   description = "Code to be executed after server build is complete."
   default     = ""
}

variable "backup" {
   description = "Provide a name"
   default     = "NONE"
}

variable "billing_cost_center" {
   description = "Provide a cost center for billing reporting"
   default     = "<COST_CENTER_CODE>"
}

variable "resource_contact" {
   description = "Provide an email"
}

variable "resource_purpose" {
   description = "Provide a description of what your using this for"
}
