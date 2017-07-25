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
   
   vars {
      custodian_queue = "${var.custodian_queue}"
      s3_custodian_log_bucket = "${var.s3_custodian_log_bucket}"
   }
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
   name                      = "as-${var.name}-${var.environment}"
   max_size                  = "${var.worker_count_max}"
   min_size                  = "${var.worker_count_min}"
   health_check_grace_period = "${var.health_check_grace_period}"
   health_check_type         = "ELB"

   launch_configuration = "${aws_launch_configuration.as_conf.name}"
   vpc_zone_identifier  = "${var.vpc_zone_identifier}"
   enabled_metrics      = ["GroupMinSize", "GroupInServiceInstances", "GroupTotalInstances", "GroupStandbyInstances", "GroupPendingInstances", "GroupTerminatingInstances", "GroupDesiredCapacity", "GroupMaxSize"]

   lifecycle {
      create_before_destroy = true
   }

   tag {
      key                 = "Name"
      value               = "${var.name}-${var.reference}-as"
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

# Cloud Watch alarms for triggering autoscaling. 
resource "aws_cloudwatch_metric_alarm" "sqs_scale_out" {
   alarm_name          = "${var.name}-${var.reference}-visible-queue-GreaterThanOrEqualTo-1"
   comparison_operator = "GreaterThanOrEqualToThreshold"
   metric_name         = "ApproximateNumberOfMessagesVisible"
   namespace           = "AWS/SQS"
   statistic           = "Average"
   period              = "60"
   evaluation_periods  = "2"
   threshold           = "1"
   dimensions {
      QueueName = "${var.custodian_queue_name}"
   }
   alarm_description = "This metric monitors approximate count of visible messages for pending messages"
   alarm_actions     = ["${aws_autoscaling_policy.sqs_scale_out.arn}"]
}

resource "aws_autoscaling_policy" "sqs_scale_out" {
   name                   = "${var.name}-${var.reference}-sqs-scale-out"
   scaling_adjustment     = 10
   adjustment_type        = "ChangeInCapacity"
   autoscaling_group_name = "${aws_autoscaling_group.as_ec2.name}"
   policy_type            = "SimpleScaling"
   cooldown               = "1200"
}

resource "aws_cloudwatch_metric_alarm" "sqs_scale_in" {
   alarm_name          = "${var.name}-${var.reference}-visible-queue-LessThanOrEqualTo-0"
   comparison_operator = "LessThanOrEqualToThreshold"
   metric_name         = "ApproximateNumberOfMessagesVisible"
   namespace           = "AWS/SQS"
   statistic           = "Average"
   period              = "300"
   evaluation_periods  = "4"
   threshold           = "0"
   dimensions {
      QueueName = "${var.custodian_queue_name}"
   }
   alarm_description = "This metric monitors approximate count of visible messages for empty queue"
   alarm_actions     = ["${aws_autoscaling_policy.sqs_scale_in.arn}"]
}

resource "aws_autoscaling_policy" "sqs_scale_in" {
   name                   = "${var.name}-${var.reference}-sqs-scale-in"
   scaling_adjustment     = -10
   adjustment_type        = "ChangeInCapacity"
   autoscaling_group_name = "${aws_autoscaling_group.as_ec2.name}"
   policy_type            = "SimpleScaling"
   cooldown               = "1200"
}