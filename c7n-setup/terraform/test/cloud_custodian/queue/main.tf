# CONFIGURE DEAD LETTER QUEUE
module "cloud-custodian-DLQ" {
   source = "../../../modules/services/aws_sqs/aws_sqs_queue"   
   name   = "${var.cc_dl_queue_name}"
}

# CONFIGURE CUSTODIAN QUEUE
module "cloud-custodian" {
   source                        = "../../../modules/services/aws_sqs/aws_sqs_queue"
   name                          = "${var.cc_queue_name}"
   message_retention_seconds     = "${var.message_retention_seconds}"
   redrive_policy                = "{\"deadLetterTargetArn\":\"${module.cloud-custodian-DLQ.arn}\",\"maxReceiveCount\":${var.dead_letter_maxReceiveCount}}"
   visibility_timeout_seconds    = "${var.cc_visibility_timeout_seconds}"
}

# CONFIGURE CUSTODIAN MAILER QUEUE
module "cloud-custodian-mailer" {
   source                        = "../../../modules/services/aws_sqs/aws_sqs_queue"   
   name                          = "${var.cc_mailer_queue_name}"
   message_retention_seconds     = "${var.mailer_message_retention_seconds}"
   receive_wait_time_seconds     = "${var.mailer_receive_wait_time_seconds}"
}