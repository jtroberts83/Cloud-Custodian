provider "aws" {
   region     = "us-east-1"
   access_key = "AKI111111111111111113VPA"
   secret_key = "KDFiosdfdjO/SDDFEfdfa/AFGEfsfdgrywefeafd"
}

terraform {
  backend "s3" {
    bucket = "<CLOUD-CUSTODIAN-BUCKET-NAME-HERE>"
    key    = "terraform-state/cloud-custodian/tst/terraform.tfstate"
    region = "us-east-1"
    access_key = "AKI111111111111111113VPA"
    secret_key = "KDFiosdfdjO/SDDFEfdfa/AFGEfsfdgrywefeafd"
  }
}

# CREATE SQS QUEUE
module "cc_queue" {
   source               = "./queue"
   cc_queue_name        = "${var.custodian_queue_name}"
   cc_dl_queue_name     = "${var.custodian_queue_name-dlq}" 
   cc_mailer_queue_name = "${var.agt-cloud-custodian-mailer}"
}


# CREATE AUTOSCALING GROUP
module "auto_scaling_group" {
   source                  = "./auto_scale_group"
   s3_custodian_log_bucket = "${var.s3_custodian_log_bucket}"
   custodian_queue         = "${module.cc_queue.queue_id}" 
   custodian_queue_name    = "${var.custodian_queue_name}"
}

# CREATE LAMBDA QUEUE INSERTER FUNCTION
module "inserter_lambda" {
   source                  = "./lambda"
   custodian_queue         = "${module.cc_queue.queue_id}"
}

# CREATE SCHEDULE
module "custodian_schedule" {
   source                  = "./schedule"
}