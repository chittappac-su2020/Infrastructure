provider "aws" {
    region = var.aws_region
}

variable "newTag" {
    type = "string"
}

resource "aws_vpc" "csye6225_demo_vpc" {
    cidr_block = var.vpc_cidr
    enable_dns_hostnames = true
    enable_dns_support = true
    enable_classiclink_dns_support = true
    assign_generated_ipv6_cidr_block = false

    tags = {
        Name = "csye6225-vpc",
        Tag2 = "new tag"
    }
}

resource "aws_subnet" "subnet" {
    cidr_block = var.subnet_cidr
    vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
    availability_zone = var.subnet_availzone
    map_public_ip_on_launch = true

    tags = {
        Name = "csye6225-subnet",
        Tag2 = "${var.newTag}"
    }
}

resource "aws_subnet" "subnet2" {
    cidr_block = var.subnet2_cidr
    vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
    availability_zone = var.subnet2_availzone
    map_public_ip_on_launch = true

    tags = {
        Name = "csye6225-subnet",
        Tag2 = "${var.newTag}"
    }
}

resource "aws_subnet" "subnet3" {
    cidr_block = var.subnet3_cidr
    vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
    availability_zone = var.subnet3_availzone
    map_public_ip_on_launch = true

    tags = {
        Name = "csye6225-subnet",
        Tag2 = "${var.newTag}"
    }
}

resource "aws_internet_gateway" "main" {
  vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
  tags = {
      Name = "csye6225-internet-gateway"
  }
}

resource "aws_route_table" "routetable" {
  vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"

  route{
      cidr_block = var.route_cidr
      gateway_id = "${aws_internet_gateway.main.id}"
  }

  tags = {
      Name = "csye6225-route-table"
  }
}

resource "aws_route_table_association" "routetableassociation" {
  subnet_id = "${aws_subnet.subnet.id}" 
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route_table_association" "routetableassociation2" {
  subnet_id = "${aws_subnet.subnet2.id}" 
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route_table_association" "routetableassociation3" {
  subnet_id = "${aws_subnet.subnet3.id}" 
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_security_group" "application" {
  name = "application"
  description = "Allowing HTTP connections"
  vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
  ingress{
      description = "ssh"
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress{
      description = "http"
      from_port = 80
      to_port = 80
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress{
      description = "https"
      from_port = 443
      to_port = 443
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress{
      description = "react server"
      from_port = 3000
      to_port = 3000
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress{
      description = "node server"
      from_port = 5000
      to_port = 5000
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress{
      description = "ssh"
      from_port = 22
      to_port = 22
      protocol = "tcp"
      ipv6_cidr_blocks = ["::/0"]
  }
  ingress{
      description = "http"
      from_port = 80
      to_port = 80
      protocol = "tcp"
      ipv6_cidr_blocks = ["::/0"]
  }
  ingress{
      description = "https"
      from_port = 443
      to_port = 443
      protocol = "tcp"
      ipv6_cidr_blocks = ["::/0"]
  }
  ingress{
      description = "react server"
      from_port = 3000
      to_port = 3000
      protocol = "tcp"
      ipv6_cidr_blocks = ["::/0"]
  }
  ingress{
      description = "node server"
      from_port = 5000
      to_port = 5000
      protocol = "tcp"
      ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    "Name" = "application"
  }
}

resource "aws_security_group" "database" {
  name = "database"
  description = "Allowing incomming database connections"
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  ingress{
      from_port = 3306
      to_port = 3306
      protocol = "tcp"
      security_groups = [aws_security_group.application.id]
  }
  tags = {
    "Name" = "database"
  }
}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket" "webapp" {
  bucket = "webapp.chandrakanth.chittappa"
  acl    = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      "rule"      = "log" 
      "autoclean" = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET"]
    allowed_origins = ["*"]
  }
}

data "aws_subnet_ids" "list" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id
}

resource "aws_db_subnet_group" "subnet_group_for_database_instance" {
  name       = "subnet_group_for_rds_instance"
  subnet_ids = ["${element(tolist(data.aws_subnet_ids.list.ids), 0)}", "${element(tolist(data.aws_subnet_ids.list.ids), 1)}"]

  tags = {
    Name = "subnet_group_for_database_instance"
  }
}

resource "aws_db_instance" "csye6225" {
  allocated_storage          = 20
  storage_type               = "gp2"
  engine                     = "mysql"
  engine_version             = "5.7"
  instance_class             = "db.t3.micro"
  name                       = "csye6225"
  username                   = "csye6225_su2020"
  password                   = "Chandrakanth1234"
  parameter_group_name       = "default.mysql5.7"
  multi_az                   = false
  identifier                 = "csye6225-su2020"
  db_subnet_group_name       = aws_db_subnet_group.subnet_group_for_database_instance.name
  publicly_accessible        = false
  vpc_security_group_ids     = [aws_security_group.database.id]
  final_snapshot_identifier  = "db1-final-snapshot"
  skip_final_snapshot        = "true"
}

resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"
  path = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    Name = "CodeDeployServiceRole"
  }
}

resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  path = "/"
  force_detach_policies = "true"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_instance" "webinstance" {
  ami           = var.AMIid
  instance_type = "t2.micro"
  vpc_security_group_ids = ["${aws_security_group.application.id}"]
  subnet_id   = "${aws_subnet.subnet.id}"
  iam_instance_profile = "${aws_iam_instance_profile.deployment_profile.name}"
  associate_public_ip_address = "true"
  key_name = "ssh"
  disable_api_termination = false
  
  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name = "Wep_App_Instance"
  }

  user_data = <<-EOF
                #!/bin/bash
                sudo echo RDS_USERNAME=${aws_db_instance.csye6225.username} >> userdata.txt
                sudo echo RDS_DATABASE_NAME=${aws_db_instance.csye6225.name} >> userdata.txt
                sudo echo RDS_PASSWORD=${aws_db_instance.csye6225.password} >> userdata.txt
                sudo echo RDS_HOSTNAME=${aws_db_instance.csye6225.address} >> userdata.txt
                sudo echo S3_BUCKET_NAME=${aws_s3_bucket.webapp.bucket} >> userdata.txt
                sudo echo APPLICATION_ENV=prod >> userdata.txt   
                sudo echo bucket=webapp.chandrakanth.chittappa >> userdata.txt
                sudo echo AWSAccessKeyId=${var.access_key} >> userdata.txt
                sudo echo AWSSecretKey=${var.secret_key} >> userdata.txt
                chmod 765 userdata.txt
  EOF
}

resource "aws_iam_instance_profile" "deployment_profile" {
  name = "deployment_profile"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

resource "aws_dynamodb_table" "csye6225" {
  name             = "csye6225"
  hash_key         = "id"
  billing_mode     = "PROVISIONED"
  read_capacity    = 20
  write_capacity   = 20
  
  attribute {
    name = "id"
    type = "S"
  }
}

#

resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "EC2 s3 access policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.codedeploy.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.codedeploy.bucket}/*"
            ]
        }
    ]
}
  EOF
}

resource "aws_iam_role" "EC2_CSYE6225" {
  name               = "EC2-CSYE6225"
  path               = "/system/"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
}
  EOF
  tags = {
    role = "ec2-access"
  }
}

resource "aws_iam_role_policy_attachment" "EC2-CSYE6225_WebAppS3" {
  role       = aws_iam_role.EC2_CSYE6225.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}

resource "aws_iam_instance_profile" "s3_profile" {
  name = "s3_profile_for_webapp"
  role = aws_iam_role.EC2_CSYE6225.name
}

resource "aws_s3_bucket" "codedeploy" {
  bucket = "codedeploy.chandrakanthchittappa.site"
  acl    = "private"
  force_destroy = "true"
  tags = "${
      map(
        "Name", "${var.dname}",
        )
    }"

  lifecycle_rule {
    id      = "log/"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    expiration {
      days = 60
    }
  }
}

resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  path        = "/"
  description = "Allows EC2 instances to read data from S3 buckets"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:DeleteObject"
	    ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.codedeploy.arn}",
		 	  "${aws_s3_bucket.codedeploy.arn}/*"
      ]
    }
  ]
}
  EOF
}

resource "aws_iam_policy" "CircleCI-Upload-To-S3" {
  name        = "CircleCI-Upload-To-S3"
  path        = "/"
  description = "Allows CircleCI to upload artifacts from latest successful build to dedicated S3 bucket used by code deploy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
          "Action": [
            "s3:PutObject",
            "s3:PutObjectAcl",
            "s3:Get*",
            "s3:List*"
            ],
			    "Effect": "Allow",
          "Resource": [
            "${aws_s3_bucket.codedeploy.arn}",
            "${aws_s3_bucket.codedeploy.arn}/*"
          ] 
			}
    ]
}
EOF
}

data "aws_caller_identity" "current" {}

locals {
  user_account_id = "${data.aws_caller_identity.current.account_id}"
}

resource "aws_iam_policy" "CircleCI-Code-Deploy" {
  name        = "CircleCI-Code-Deploy"
  path        = "/"
  description = "Allows CircleCI to call CodeDeploy APIs to initiate application deployment on EC2 instances"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource":
        "arn:aws:codedeploy:${var.aws_region}:${local.user_account_id}:application:${aws_codedeploy_app.csye6225-webapp.name}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": "*"
  },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${local.user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${local.user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${local.user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
	  ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "circleci-ec2-ami" {
  name = "circleci-ec2-ami"
  path = "/"
  description = "This policy helps to avoid credentials"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "${aws_s3_bucket.codedeploy.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "codedeploy_role_ec2role" {
    role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
    policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
}

resource "aws_iam_role_policy_attachment" "codedeploy_role_servicerole" {
 role       = "${aws_iam_role.CodeDeployServiceRole.name}"
 policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "Wep_App_Instance"
    }
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  alarm_configuration {
    alarms  = ["my-alarm-name"]
    enabled = true
  }
}












































