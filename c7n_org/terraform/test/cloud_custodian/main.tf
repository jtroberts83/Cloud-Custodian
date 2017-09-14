provider "aws" {
    region  = "${var.region}"
    assume_role {
        role_arn = "arn:aws:iam::${var.account_number}:role/${var.role_name}"
    }
}


terraform {
  backend "s3" {
    bucket = "<S3_TERRAFORM_BUCKET_NAME>"
    key    = "terraform-state/cloud-custodian/prd/terraform.tfstate"
    region = "us-east-1"
  }
}

# CREATE SQS QUEUE
module "cc_queue" {
   source               = "./queue"
   cc_mailer_queue_name = "${var.cloud-custodian-mailer}"
}


# CREATE AUTOSCALING GROUP
module "auto_scaling_group" {
   source                  = "./auto_scale_group"
}
