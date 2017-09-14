
variable "cc_mailer_queue_name" {
   description = "The name of the queue that cloud custodian will leverage for mail."
   default     = "cloud-custodian-mailer"
}

variable "mailer_message_retention_seconds" {
   description = ""
   default     = 1209600
}

variable "mailer_receive_wait_time_seconds" {
   description = ""
   default     = 20
}