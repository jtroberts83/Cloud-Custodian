output "arn" {
   value = "${aws_lambda_function.aws_lambda_function_file.arn}"
}

output "qualified_arn" {
   value = "${aws_lambda_function.aws_lambda_function_file.qualified_arn}"
}

output "invoke_arn" {
   value = "${aws_lambda_function.aws_lambda_function_file.invoke_arn}"
}

output "version" {
   value = "${aws_lambda_function.aws_lambda_function_file.version}"
}

output "last_modified" {
   value = "${aws_lambda_function.aws_lambda_function_file.last_modified}"
}

output "kms_key_arn" {
   value = "${aws_lambda_function.aws_lambda_function_file.kms_key_arn}"
}

output "source_code_hash" {
   value = "${aws_lambda_function.aws_lambda_function_file.source_code_hash}"
}
