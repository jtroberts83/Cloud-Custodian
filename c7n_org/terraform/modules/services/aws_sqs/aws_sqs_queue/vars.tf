variable "name" {
   description = "This is the human-readable name of the queue"
}

variable "delay_seconds" {
   description = "The time in seconds that the delivery of all messages in the queue will be delayed. An integer from 0 to 900 (15 minutes). The default for this attribute is 0 seconds."
   default     = 0
}

variable "max_message_size" {
   description = "The limit of how many bytes a message can contain before Amazon SQS rejects it. An integer from 1024 bytes (1 KiB) up to 262144 bytes (256 KiB). The default for this attribute is 262144 (256 KiB)."
   default     = 262144
}

variable "message_retention_seconds" {
   description = "The number of seconds Amazon SQS retains a message. Integer representing seconds, from 60 (1 minute) to 1209600 (14 days). The default for this attribute is 345600 (4 days)."
   default     = 345600
}

variable "receive_wait_time_seconds" {
   description = "The time for which a ReceiveMessage call will wait for a message to arrive (long polling) before returning. An integer from 0 to 20 (seconds). The default for this attribute is 0, meaning that the call will return immediately."
   default     = 20
}

variable "redrive_policy" {
   description = "The JSON policy to set up the Dead Letter Queue, see AWS docs. Note: when specifying maxReceiveCount, you must specify it as an integer (5), and not a string. Example - {\"deadLetterTargetArn\":\"${aws_sqs_queue.terraform_queue_deadletter.arn}\",\"maxReceiveCount\":4}"
   default     = ""
}

variable "fifo_queue" {
   description = "Boolean designating a FIFO queue. If not set, it defaults to false making it standard."
   default     = false
}

variable "content_based_deduplication" {
   description = "Enables content-based deduplication for FIFO queues."
   default     = false
}

variable "visibility_timeout_seconds" {
   description = "The visibility timeout for the queue. An integer from 0 to 43200 (12 hours). The default for this attribute is 30."
   default     = 30
}