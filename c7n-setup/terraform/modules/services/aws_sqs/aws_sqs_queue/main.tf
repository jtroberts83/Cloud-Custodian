resource "aws_sqs_queue" "aws_sqs_queue" {
  name                        = "${var.name}"
  delay_seconds               = "${var.delay_seconds}"
  max_message_size            = "${var.max_message_size}"
  message_retention_seconds   = "${var.message_retention_seconds}"
  receive_wait_time_seconds   = "${var.receive_wait_time_seconds}"
  redrive_policy              = "${var.redrive_policy}"
  fifo_queue                  = "${var.fifo_queue}"
  content_based_deduplication = "${var.content_based_deduplication}"
  visibility_timeout_seconds  = "${var.visibility_timeout_seconds}"
}
