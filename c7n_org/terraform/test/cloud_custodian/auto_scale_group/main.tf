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

data "template_file" "user_data" {
   template = "${file("${path.module}/userdata.tpl")}"
}

resource "aws_launch_configuration" "as_conf" {
   name_prefix   = "${var.name}-${var.reference}-"
   image_id      = "${data.aws_ami.aws-ami.id}"
   instance_type = "${var.instance_size}"

   root_block_device {
      volume_type           = "gp2"
      volume_size           = "${var.root_volume_size}"
      delete_on_termination = true
   }

   ebs_block_device {
      device_name           = "/dev/xvdcz"
      volume_type           = "gp2"
      volume_size           = "${var.root_volume_size}"
      encrypted             = true
      delete_on_termination = true
   }

   iam_instance_profile = "${var.iam_role}"
   key_name             = "${var.ec2_keypair}"
   security_groups      = "${var.ec2_security_groups}"
   user_data            = "${data.template_file.user_data.rendered}"
   ebs_optimized        = "${var.ebs_optimized}"

   lifecycle {
      create_before_destroy = true
   }
}

resource "aws_autoscaling_group" "as_ec2" {
   name                      = "${var.name}"
   max_size                  = "${var.worker_count_max}"
   min_size                  = "${var.worker_count_min}"
   health_check_grace_period = "${var.health_check_grace_period}"
   health_check_type         = "EC2"

   launch_configuration = "${aws_launch_configuration.as_conf.name}"
   vpc_zone_identifier  = "${var.vpc_zone_identifier}"
   enabled_metrics      = ["GroupMinSize", "GroupInServiceInstances", "GroupTotalInstances", "GroupStandbyInstances", "GroupPendingInstances", "GroupTerminatingInstances", "GroupDesiredCapacity", "GroupMaxSize"]

   lifecycle {
      create_before_destroy = true
   }

   tag {
      key                 = "Name"
      value               = "${var.name}"
      propagate_at_launch = true
   }

   tag {
      key                 = "Backup"
      value               = "${var.backup}"
      propagate_at_launch = true
   }

   tag {
      key                 = "Billing Cost Center"
      value               = "${var.billing_cost_center}"
      propagate_at_launch = true
   }

   tag {
      key                 = "Environment"
      value               = "${var.environment}"
      propagate_at_launch = true
   }

   tag {
      key                 = "Resource Contact"
      value               = "${var.resource_contact}"
      propagate_at_launch = true
   }

   tag {
      key                 = "Resource Purpose"
      value               = "${var.resource_purpose}"
      propagate_at_launch = true
   }
}

resource "aws_autoscaling_schedule" "instances_scaleup_BusinessHours" {
  scheduled_action_name  = "AGT-Cloud-Custodian-Org-Runner-scaleup" 
  min_size               = "1"
  max_size               = "1"
  desired_capacity       = "1"
  recurrence             = "0 14 * * *"
  autoscaling_group_name = "${aws_autoscaling_group.as_ec2.name}"
}

resource "aws_autoscaling_notification" "Failure_notifications" {
  group_names = [
    "${aws_autoscaling_group.as_ec2.name}",
  ]

  notifications = [
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
  ]

  topic_arn = "arn:aws:sns:us-east-1:969859503720:JamisonTest"
}