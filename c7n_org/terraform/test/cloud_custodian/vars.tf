variable "account_number" {
    description = "Account number everything is executed in."
	default     = "969859503720"
}

variable "region" {
    description = "Region everything is executed in."
    default     = "us-east-1"
}

variable "role_name" {
    description = "role name everyting is executed as"
    default     = "agt-cloudteam-tools"
}

variable "agt-cloud-custodian-mailer" {
   description = "The name of the queue that cloud custodian will leverage for mail."
   default     = "agt-cloud-custodian-mailer"
}
