variable "filename" {
   description = "The path to the function's deployment package within the local filesystem. If defined, The s3_-prefixed options cannot be used."
}

variable "function_name" {
   description = "A unique name for your Lambda Function."
}

variable "description" {
   description = "Description of what your Lambda Function does."
   default = ""
}

variable "role_arn" {
   description = "IAM role attached to the Lambda Function. This governs both who / what can invoke your Lambda Function, as well as what resources our Lambda Function has access to. See Lambda Permission Model for more details."
}

variable "handler" {
   description = "The function entrypoint in your code."
}

variable "runtime" {
   description = "Valid Values: nodejs | nodejs4.3 | nodejs6.10 | java8 | python2.7 | python3.6 | dotnetcore1.0 | nodejs4.3-edge"
}

variable "variable_map" {
   type = "map"
   description = "A map that defines environment variables for the Lambda function."
   default     = {}
}

variable "publish" {
   description =  "Whether to publish creation/change as new Lambda Function Version. Defaults to false."
   default     = false
}

variable "memory_size" {
   description = "Amount of memory in MB your Lambda Function can use at runtime. Defaults to 128. See Limits"
   default     = "128"
}

variable "timeout" {
   description = "The timeout value of the job.  Default is 3 seconds."
   default     = "3"
}