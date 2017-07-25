# CREATE LAMBDA INITIATOR FUNCTION
resource "aws_lambda_function" "aws_lambda_function_file" {
   filename         = "${var.filename}"
   source_code_hash = "${base64sha256(file("${var.filename}"))}"
   function_name    = "${var.function_name}"
   description      = "${var.description}"
   role             = "${var.role_arn}"
   handler          = "${var.handler}"
   runtime          = "${var.runtime}"
   publish          = "${var.publish}"
   memory_size      = "${var.memory_size}"
   timeout          = "${var.timeout}"
   
   environment {
      variables = "${var.variable_map}"
  }
}