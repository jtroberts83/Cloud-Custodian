variable s3_custodian_log_bucket {
   description = "The S3 bucket used for Cloud Custodian logging"
   default     =  "cloud-custodian"
}

variable "custodian_queue_name" {
   description = "The name of the custodian queue"
   default     = "cloud-custodian"
}

variable "custodian_queue_name-dlq" {
   description = "The name of the queue that cloud custodian will leverage for dead letter."
   default     = "cloud-custodian-DLQ"
}

variable "agt-cloud-custodian-mailer" {
   description = "The name of the queue that cloud custodian will leverage for mail."
   default     = "cloud-custodian-mailer"
}
