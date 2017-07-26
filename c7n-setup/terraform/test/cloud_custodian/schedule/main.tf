
resource "aws_cloudwatch_event_rule" "custodian_scheduler" {
   name                = "Custodian-WorkInserter"
   schedule_expression = "cron(0 16 * * ? *)"
   description         = "This is a schedule used to initiate the Lambda job that populates the SQS queue for Cloud Custodian workers"
   role_arn            = "arn:aws:iam::<ACCOUNT-NUMBER>:role/Cloud_Custodian_Role"
   is_enabled          = "true"
}


resource "aws_cloudwatch_event_target" "Custodian-WorkInserter" {
  rule      = "${aws_cloudwatch_event_rule.custodian_scheduler.name}"
  arn       = "arn:aws:lambda:us-east-1:<ACCOUNT-NUMBER>:function:Custodian-WorkInserter"
}
