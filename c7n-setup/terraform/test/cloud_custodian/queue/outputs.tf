output "queue_id" {
   value = "${module.cloud-custodian.id}"
}

output "queue_arn" {
   value = "${module.cloud-custodian.arn}"
}

output "dl_queue_id" {
   value = "${module.cloud-custodian-DLQ.id}"
}

output "dl_queue_arn" {
   value = "${module.cloud-custodian-DLQ.arn}"
}
