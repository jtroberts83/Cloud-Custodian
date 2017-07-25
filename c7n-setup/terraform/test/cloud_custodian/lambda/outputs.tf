output "arn" {
   value = "${aws_lambda_function.cloud-custodian-initiator.arn}"
}

output "qualified_arn" {
   value = "${aws_lambda_function.cloud-custodian-initiator.qualified_arn}"
}

output "invoke_arn" {
   value = "${aws_lambda_function.cloud-custodian-initiator.invoke_arn}"
}

output "version" {
   value = "${aws_lambda_function.cloud-custodian-initiator.version}"
}

output "last_modified" {
   value = "${aws_lambda_function.cloud-custodian-initiator.last_modified}"
}

output "kms_key_arn" {
   value = "${aws_lambda_function.cloud-custodian-initiator.kms_key_arn}"
}

output "source_code_hash" {
   value = "${aws_lambda_function.cloud-custodian-initiator.source_code_hash}"
}
