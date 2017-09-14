
# CONFIGURE CUSTODIAN MAILER QUEUE
module "cloud-custodian-mailer" {
   source                        = "../../../modules/services/aws_sqs/aws_sqs_queue"   
   name                          = "${var.cc_mailer_queue_name}"
   message_retention_seconds     = "${var.mailer_message_retention_seconds}"
   receive_wait_time_seconds     = "${var.mailer_receive_wait_time_seconds}"
}