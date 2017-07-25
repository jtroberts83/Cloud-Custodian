variable "cc_queue_name" {
   description = "The name of the queue that cloud custodian will leverage."
   default     = "cloud-custodian"
}

variable "cc_dl_queue_name" {
   description = "The name of the queue that cloud custodian will leverage."
   default     = "cloud-custodian-DLQ"
}

variable "cc_visibility_timeout_seconds" {
   description = "The visibility timeout for the queue. An integer from 0 to 43200 (12 hours). The default for this attribute is 30."
   default     = 300
}

variable "dead_letter_maxReceiveCount" {
   description = "The maximum receive count for dead letters."
   default     = 4
}

variable "message_retention_seconds" {
   description = ""
   default     = 3540
}

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
   default     = "20"
}