# CREATE LAMBDA INITIATOR FUNCTION
resource "aws_lambda_function" "cloud-custodian-initiator" {
   filename         = "${path.module}/${var.initiator_filename}"
   source_code_hash = "${base64sha256(file("${path.module}/${var.initiator_filename}"))}"
   function_name    = "${var.initiator_function_name}"
   description      = "${var.initiator_description}"
   role             = "${var.initiator_role_arn}"
   handler          = "${var.initiator_handler}"
   runtime          = "${var.initiator_runtime}"
   publish          = "${var.initiator_publish}"
   memory_size      = "${var.initiator_memory_size}"
   timeout          = "${var.initiator_timeout}"
   
   environment {
      variables = {
         QUEUE_URL  = "${var.custodian_queue}"
    }
  }
}