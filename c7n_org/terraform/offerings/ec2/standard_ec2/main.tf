data "aws_ami" "aws-ami" {
   most_recent = true

   filter {
      name   = "name"
      values = ["${var.ami_name}"]
   }

   filter {
      name   = "virtualization-type"
      values = ["hvm"]
   }

   filter {
      name   = "tag:Encrypted"
      values = ["TRUE"]
  }

   owners = ["${var.ami_owner_account}"]
}

resource "aws_instance" "ec2_instance" {
   ami           = "${data.aws_ami.aws-ami.id}"
   instance_type = "${var.instance_size}"

   count                   = "${var.instance_count}"
   monitoring              = "${var.monitoring}"
   user_data               = "${var.user_data}"
   subnet_id               = "${var.subnet_id}"
   iam_instance_profile    = "${var.iam_role}"
   key_name                = "${var.ec2_keypair}"
   vpc_security_group_ids  = "${var.vpc_security_groups}"
   ebs_optimized           = "${var.ebs_optimized}"

   root_block_device {
      volume_type           = "gp2"
      volume_size           = "${var.root_volume_size}"
      delete_on_termination = true
   }
   
   lifecycle {
      create_before_destroy = true
   }

   tags {
     Name               = "${var.name}-${var.reference}"
     Backup             = "${var.backup}"
     "Resource Contact" = "${var.resource_contact}"
     Environment        = "${var.reference}"
     "Resource Purpose" = "${var.resource_purpose}"
   }
}
