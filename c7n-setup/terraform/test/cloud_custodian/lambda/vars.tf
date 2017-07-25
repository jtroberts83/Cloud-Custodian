variable "initiator_function_name" {
   description = "The name of the lambda function that inserts custodian work into SQS."
   default     = "Custodian-WorkInserter"
}

variable "initiator_filename" {
   description = "The path to the function's deployment package within the local filesystem. If defined, The s3_-prefixed options cannot be used."
   default     = "Custodian-WorkInserter.zip"
}

variable "initiator_description" {
   description = "Description of what your Lambda Function does."
   default = "This function inserts job information into the Custodian SQS queue"
}

variable "initiator_role_arn" {
   description = "IAM role attached to the Lambda Function. This governs both who / what can invoke your Lambda Function, as well as what resources our Lambda Function has access to. See Lambda Permission Model for more details."
   default = "arn:aws:iam::<ACCOUNT-NUMBER-HERE>:role/AGT_Cloud_Custodian_Role"
}

variable "initiator_handler" {
   description = "The function entrypoint in your code."
   default     = "lambda.lambda_handler"
}

variable "initiator_runtime" {
   description = "Valid Values: nodejs | nodejs4.3 | nodejs6.10 | java8 | python2.7 | python3.6 | dotnetcore1.0 | nodejs4.3-edge"
   default = "python2.7"
}

variable "initiator_publish" {
   description =  "Whether to publish creation/change as new Lambda Function Version. Defaults to false."
   default     = false
}

variable "initiator_memory_size" {
   description = "Amount of memory in MB your Lambda Function can use at runtime. Defaults to 128. See Limits"
   default     = "128"
}

variable "custodian_queue" {
   description = "The URL of the SQS Queue used for Cloud Custodian"
}

variable "initiator_timeout" {
   description = "The timeout value of the job.  Default is 3 seconds."
   default     = "180"
}