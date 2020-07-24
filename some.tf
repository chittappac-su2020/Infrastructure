variable "aws_region" {
   type = string
default="us-east-1"
}

provider "aws" {
    region = var.aws_region
}

variable "vpc_name" {
   type = string

default="csye_custom_vpc"  
}

variable "subnet1" {
   type = string
 
default="subnet1"
}
variable "subnet2" {
   type = string
 
default="subnet2"
}
variable "subnet3" {
   type = string
  
default="subnet3"
}
variable "csye_internetgateway" {
   type = string

 default="csye_main_internetgateway"
}
variable "csye_route_table" {
   type = string

 default="csye_route_table"
}
variable "cidr_vpc" {
   type = string
   default="10.0.0.0/16"
}
variable "cidr_subnet1" {
   type = string
   default="10.0.1.0/24"
}
variable "cidr_subnet2" {
   type = string
   default="10.0.2.0/24"
}
variable "cidr_subnet3" {
   type = string
   default="10.0.3.0/24"
}
variable "cidr_route" {
   type = string
   default="0.0.0.0/0"
}
variable "avail_z1" {
   type = string
  default="us-east-1a"
}
variable "avail_z2" {
   type = string
 default="us-east-1b"
}
variable "avail_z3" {
   type = string
 default="us-east-1c"
}


resource "aws_vpc" "csye_custom_vpc" {
    cidr_block = var.cidr_vpc
    enable_dns_hostnames = true
    enable_dns_support = true
    enable_classiclink_dns_support = true
    assign_generated_ipv6_cidr_block = false
    tags = {
	    Name = var.vpc_name	
	   }
}
resource "aws_subnet" "subnet1" {
    cidr_block =  var.cidr_subnet1
    vpc_id = "${aws_vpc.csye_custom_vpc.id}"
    availability_zone = var.avail_z1
    map_public_ip_on_launch = true
    tags = {
      Name = var.subnet1
    }
}
resource "aws_subnet" "subnet2" {
    cidr_block = var.cidr_subnet2
    vpc_id = "${aws_vpc.csye_custom_vpc.id}"
    availability_zone = var.avail_z2
    map_public_ip_on_launch = true
    tags = {
        Name = var.subnet2
    }
}
resource "aws_subnet" "subnet3" {
    cidr_block = var.cidr_subnet3
    vpc_id = "${aws_vpc.csye_custom_vpc.id}"
    availability_zone = var.avail_z3
    map_public_ip_on_launch = true
    tags = {
         Name = var.subnet3
    }
}

resource "aws_internet_gateway" "csye_main_internetgateway" {
  vpc_id = "${aws_vpc.csye_custom_vpc.id}"

  tags = {
    Name = var.csye_internetgateway
  }
}

resource "aws_route_table" "csye_route_table" {
  vpc_id = "${aws_vpc.csye_custom_vpc.id}"

  route {
    cidr_block = var.cidr_route
    gateway_id = "${aws_internet_gateway.csye_main_internetgateway.id}"
  }

  tags = {
    Name = var.csye_route_table
  }
}
resource "aws_route_table_association" "association_for_subnet1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.csye_route_table.id
}

resource "aws_route_table_association" "association_for_subnet2" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.csye_route_table.id
}

resource "aws_route_table_association" "association_for_subnet3" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.csye_route_table.id
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


variable "application" {
   type = string
 
 default="application" 
}
variable "database" {
   type = string
   default="database"
}
variable "bucket" {
   type = string
   default="bucket"
}
variable "bucketName" {
   type = string
 
     default="webapp.mahesh.prasad.images"
}
variable "db_subnet_group" {
   type = string
    default="db_subnet_group" 
}
variable "my_webapp" {
   type = string
     default="my_webapp"
}
variable "WebAppS3" {
   type = string
default="WebAppS3"
}
variable "EC2-CSYE6225" {
   type = string
   default="EC2-CSYE6225"
}
variable "AMI_ID" {
   type = string
 default="ami-0f8f75c2fbec43445"
}

variable "AWSSecretKey" {
   type = string
}

variable "AWSAccessKeyId" {
   type = string
}

variable "instance_profile" {
   type = string
    default="instance_profile"
 
}

////////////////////////////////////////////////////////////////////////////////////////////////


variable "domain-name" {
   type = string
  default="webapp.maheshprasad.site"
}


///////////////////////////////////////////////////////////////////////////////////////////



resource "aws_security_group" "lb_security_grp" {
  name        = var.lb_security_grp
  description = "security group for ec2 instance"
  vpc_id      = "${aws_vpc.csye_custom_vpc.id}"


  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks=["::/0"]
  }

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks=["::/0"]
  }

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks=["::/0"]
  }

  ingress {
    description = "frontend"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks=["::/0"]
  }


  ingress {
    description = "backend"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks=["::/0"]
  }


 egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "lb_security_grp"
  }
}


resource "aws_security_group" "application" {
  name        = var.application
  description = "security group for ec2 instance"
  vpc_id      = "${aws_vpc.csye_custom_vpc.id}"


  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    security_groups = ["${aws_security_group.lb_security_grp.id}"]
  }

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = ["${aws_security_group.lb_security_grp.id}"]
  }

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = ["${aws_security_group.lb_security_grp.id}"]
  }

  ingress {
    description = "frontend"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = ["${aws_security_group.lb_security_grp.id}"]
  }


  ingress {
    description = "backend"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    security_groups = ["${aws_security_group.lb_security_grp.id}"]
  }


 egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "application"
  }
}


resource "aws_security_group" "database" {
  name        = var.database
  description = "database"
  vpc_id      = "${aws_vpc.csye_custom_vpc.id}"

  ingress {
    description = "mysql"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = ["${aws_security_group.application.id}"]
  }
 egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database"
  }
}


resource "aws_s3_bucket" "webapp_mahesh_prasad" {
  bucket = var.bucketName
  acl    = "private"
  force_destroy = true

 cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST","GET"]
    allowed_origins = ["*"]
  }

  lifecycle_rule {
    id      = "lifecycle_rule"
    enabled = true

    prefix = "lifecycle_rule/"

    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA" 
    }

    expiration {
      days = 90
    }


 

  }

    server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}


resource "aws_db_subnet_group" "db_subnet_group" {
  name       = var.db_subnet_group
  subnet_ids = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}"]

  tags = {
    Name = var.db_subnet_group
  }
}

resource "aws_db_instance" "aws_rds" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  identifier           = "rds-identifier"
  name                 = "csye6225"
  username             = "csye6225_su2020"
  password             = "password"
  parameter_group_name = "default.mysql5.7"
  multi_az             = "false" 
  publicly_accessible  = "false"
  db_subnet_group_name = "${aws_db_subnet_group.db_subnet_group.name}"
  vpc_security_group_ids = [aws_security_group.database.id]
  final_snapshot_identifier = "dbinstance1-final-snapshot"
  skip_final_snapshot       = "true"
}


resource "aws_iam_policy" "WebAppS3" {
  name        = var.WebAppS3
  description = "IAM access policy"

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
                "arn:aws:s3:::${aws_s3_bucket.webapp_mahesh_prasad.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.webapp_mahesh_prasad.bucket}/*"
            ]
        }
    ]
}
  EOF
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
      "Principal":
        {"Service": "ec2.amazonaws.com"},
      "Effect": "Allow",
	   "Sid": ""
    }
  ]
}
EOF
}


resource "aws_iam_role" "CodeDeployLambdaServiceRole" {
name           = "iam_for_lambda_with_sns"
path           = "/"
force_detach_policies = "true"
assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
tags = {
Name = "CodeDeployLambdaServiceRole"
}
}


resource "aws_iam_instance_profile" "instance_profile" {
  name = var.instance_profile
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

// resource "aws_instance" "web_app_ec2" {

//   ami           = var.AMI_ID
//   instance_type = "t2.micro"
//   vpc_security_group_ids =["${aws_security_group.application.id}"] 
//   subnet_id= "${aws_subnet.subnet1.id}"
//   iam_instance_profile= "${aws_iam_instance_profile.instance_profile.name}"
//   associate_public_ip_address="true"
//   tags = {
//     Name = "mybook_webapp"
//   }
//   key_name= var.my_webapp
//   disable_api_termination = "false"
//   root_block_device  {
//     volume_size           = "20"
//     volume_type           = "gp2"
//     delete_on_termination = "true"
//   }
//    user_data = <<-EOF
//                 #!/bin/bash
//                 sudo touch data.txt
//                 sudo echo RDS_USERNAME=${aws_db_instance.aws_rds.username} >> data.txt
//                 sudo echo RDS_DATABASENAME=${aws_db_instance.aws_rds.name} >> data.txt
//                 sudo echo RDS_PASSWORD=${aws_db_instance.aws_rds.password} >> data.txt
//                 sudo echo RDS_HOSTNAME=${aws_db_instance.aws_rds.address} >> data.txt
//                 sudo echo MySQL_HOST=${aws_db_instance.aws_rds.address} >> data.txt
//                 sudo echo ENVIRONMENT=prod >> data.txt
//                 sudo echo bucket=${aws_s3_bucket.webapp_mahesh_prasad.bucket} >> data.txt
//                 sudo echo S3_BUCKET_NAME=${aws_s3_bucket.webapp_mahesh_prasad.bucket} >> data.txt
//                 sudo echo AWSAccessKeyId=${var.AWSAccessKeyId} >> data.txt
//                 sudo echo AWSSecretKey=${var.AWSSecretKey} >> data.txt
                
                
                

//   EOF
// }


resource "aws_dynamodb_table" "csye6225" {
  name             = "csye6225"
  hash_key         = "id"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
      attribute {
    name = "id"
    type = "S"
  }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

resource "aws_s3_bucket" "bucket_codedeploy" {
	bucket = "codedeploy.${var.domain-name}"
	acl    = "private"
	force_destroy = "true"
	tags = "${
      		map(
     		"Name", "${var.domain-name}",
    		)
  	}"
	lifecycle_rule {
	    id      = "log/"
	    enabled = true
		transition{
			days = 30
			storage_class = "STANDARD_IA"
		}
		expiration{
			days = 60
		}
	}
}


// resource "aws_s3_bucket" "lambda_codedeploy" {
// 	bucket = "codedeploy.lambda.codedeploy.mahesh"
// 	acl    = "private"
// 	force_destroy = "true"
// 	tags = "${
//       		map(
//      		"Name", "lambda_codedeploy",
//     		)
//   	}"
// 	lifecycle_rule {
// 	    id      = "log/"
// 	    enabled = true
// 		transition{
// 			days = 30
// 			storage_class = "STANDARD_IA"
// 		}
// 		expiration{
// 			days = 60
// 		}
// 	}
// }

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
        "s3:DeleteObject",
        "s3:Put*",
        "s3:Delete*"
	  ],
      "Effect": "Allow",
      "Resource": [
	   			"${aws_s3_bucket.bucket_codedeploy.arn}",
		      "${aws_s3_bucket.bucket_codedeploy.arn}/*",
          "${aws_s3_bucket.webapp_mahesh_prasad.arn}",
		      "${aws_s3_bucket.webapp_mahesh_prasad.arn}/*"
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
        {"Action": [
            "s3:PutObject",
            "s3:GetObject",
            "s3:DeleteObject"
            ],
			"Effect": "Allow",
            "Resource": ["${aws_s3_bucket.bucket_codedeploy.arn}",
            "${aws_s3_bucket.bucket_codedeploy.arn}/*"]
			}
    ]
}
EOF
}




resource "aws_iam_policy" "CircleCI-uploadLambda-To-S3" {
name        = "CircleCI-uploadLambda-To-S3"
path        = "/"
description = "Allows CircleCI to upload artifacts from latest successful build to dedicated S3 bucket used by code deploy"
policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ActionsWhichSupportResourceLevelPermissions",
            "Effect": "Allow",
            "Action": [
                "lambda:AddPermission",
                "lambda:RemovePermission",
                "lambda:CreateAlias",
                "lambda:UpdateAlias",
                "lambda:DeleteAlias",
                "lambda:UpdateFunctionCode",
                "lambda:UpdateFunctionConfiguration",
                "lambda:PutFunctionConcurrency",
                "lambda:DeleteFunctionConcurrency",
                "lambda:PublishVersion"
            ],
            "Resource": "arn:aws:lambda:${var.aws_region}:${local.current_account_id}:function:csye6225"
        }
]
}
EOF
}

data "aws_caller_identity" "current" {}

locals {
  current_account_id = "${data.aws_caller_identity.current.account_id}"
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
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${local.current_account_id}:application:${aws_codedeploy_app.csye6225-webapp.name}"
      ]
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
        "arn:aws:codedeploy:${var.aws_region}:${local.current_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${local.current_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${local.current_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
	  ]
    }
  ]
}
EOF
}


resource "aws_iam_policy" "circleci-ec2-ami" {
  name        = "circleci-ec2-ami"
  path        = "/"
  description = "Allows CircleCI to upload artifacts from latest successful build to dedicated S3 bucket used by code deploy"
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
            "Resource": "${aws_s3_bucket.bucket_codedeploy.arn}" 
        }
    ]
}
EOF
}


resource "aws_iam_policy" "CloudWatchAgentServerPolicy" {
  name        = "CloudWatchAgentServerPolicy"
  path        = "/"
  description = "Adding AWS cloud watch agent to the role and policy to monitor the data flow"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:::parameter/AmazonCloudWatch-*"
        }
    ]
}
EOF
}


resource "aws_iam_user_policy_attachment" "test-attach1" {
user      = "cicd"
policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"
}
resource "aws_iam_user_policy_attachment" "test-attach2" {
user      = "cicd"
policy_arn = "${aws_iam_policy.CircleCI-Code-Deploy.arn}"
}
resource "aws_iam_user_policy_attachment" "test-attach3" {
user      = "cicd"
policy_arn = "${aws_iam_policy.CircleCI-Upload-To-S3.arn}"
}

resource "aws_iam_user_policy_attachment" "circleci-update-policy-attach" {
user      = "cicd"
policy_arn = "${aws_iam_policy.CircleCI-uploadLambda-To-S3.arn}"
}



resource "aws_iam_role_policy_attachment" "role_CloudWatchAgentServerPolicy" {
    role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
    policy_arn = "${aws_iam_policy.CloudWatchAgentServerPolicy.arn}"
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
 depends_on = [aws_iam_role.CodeDeployServiceRole,aws_autoscaling_group.auto_scaling_group]
 service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"

 ec2_tag_set {
   ec2_tag_filter {
     key   = "Name"
     type  = "KEY_AND_VALUE"
     value = "mybook_webapp"
   }
 }

 deployment_style {
   deployment_option = "WITHOUT_TRAFFIC_CONTROL"
   deployment_type   = "IN_PLACE"
 }

 deployment_config_name = "CodeDeployDefault.AllAtOnce"

 auto_rollback_configuration {
   enabled = true
   events  = [
           "DEPLOYMENT_FAILURE"
         ]
 }

  alarm_configuration {
    alarms  = ["my-alarm-name"]
    enabled = true
  }
  
  autoscaling_groups = ["auto_scaling_group"]

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

variable "lb_security_grp" {
   type = string
  
default="lb_security_grp"
}

variable "route_zone_id" {
   type = string
   default="Z0923168SHKVCUEPX8C7"
}

variable "website" {
   type = string
 default="prod.mahesh-prasad.site"
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
resource "aws_launch_configuration" "asg_launch_config" {
  name = "asg_launch_config"
  image_id = var.AMI_ID
  instance_type = "t2.micro"
  key_name = var.my_webapp
  iam_instance_profile= "${aws_iam_instance_profile.instance_profile.name}"
  associate_public_ip_address = true
  user_data = <<-EOF
                #!/bin/bash
                sudo touch data.txt
                sudo echo RDS_USERNAME=${aws_db_instance.aws_rds.username} >> data.txt
                sudo echo RDS_DATABASENAME=${aws_db_instance.aws_rds.name} >> data.txt
                sudo echo RDS_PASSWORD=${aws_db_instance.aws_rds.password} >> data.txt
                sudo echo RDS_HOSTNAME=${aws_db_instance.aws_rds.address} >> data.txt
                sudo echo MySQL_HOST=${aws_db_instance.aws_rds.address} >> data.txt
                sudo echo ENVIRONMENT=prod >> data.txt
                sudo echo bucket=${aws_s3_bucket.webapp_mahesh_prasad.bucket} >> data.txt
                sudo echo S3_BUCKET_NAME=${aws_s3_bucket.webapp_mahesh_prasad.bucket} >> data.txt
                sudo echo AWSAccessKeyId=${var.AWSAccessKeyId} >> data.txt
                sudo echo AWSSecretKey=${var.AWSSecretKey} >> data.txt
  EOF
  security_groups = ["${aws_security_group.application.id}"]
}


resource "aws_lb" "my-load-Balancer" {
  name = "my-load-Balancer"
  load_balancer_type = "application"
  enable_deletion_protection = false
  subnets = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}"]
  security_groups = ["${aws_security_group.lb_security_grp.id}"]
}


resource "aws_lb_target_group" "target-group-autoscale1" {
  name = "target-group-autoscale1"
  target_type = "instance"
  port = 3000
  protocol = "HTTP"
  vpc_id = "${aws_vpc.csye_custom_vpc.id}"
}

resource "aws_lb_listener" "lb_listener1" {
  load_balancer_arn = aws_lb.my-load-Balancer.arn
  port = 80
  protocol = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.target-group-autoscale1.arn
    }
}

resource "aws_lb_target_group" "target-group-autoscale2" {
  name = "target-group-autoscale2"
  target_type = "instance"
  port = 8080
  protocol = "HTTP"
  vpc_id = "${aws_vpc.csye_custom_vpc.id}"
}

resource "aws_lb_listener" "lb_listener2" {
  load_balancer_arn = aws_lb.my-load-Balancer.arn
  port = 8080
  protocol = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.target-group-autoscale2.arn
  }
}

resource "aws_autoscaling_group" "auto_scaling_group" {
  name = "auto_scaling_group"
  default_cooldown = 60
  max_size = 5
  min_size = 2
  desired_capacity = 2
  launch_configuration = aws_launch_configuration.asg_launch_config.name
  target_group_arns = [aws_lb_target_group.target-group-autoscale1.arn,aws_lb_target_group.target-group-autoscale2.arn]
  vpc_zone_identifier = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}","${aws_subnet.subnet3.id}"]
  tag {
    key = "my_webapp"
    value = "Imsherlocked44$"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "auto_scaling_policyUp" {
  name = "auto_scaling_policyUp"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 60
  autoscaling_group_name = aws_autoscaling_group.auto_scaling_group.name
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  threshold           = "3"
  period              = "120"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  alarm_description = "Scale-down if CPU < 70% for 10 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.auto_scaling_policyDown.arn}"]
  dimensions = {
    AutoScalingGroupName = "auto_scaling_group" 
  }
}

resource "aws_autoscaling_policy" "auto_scaling_policyDown" {
  name = "auto_scaling_policyDown"
  scaling_adjustment = -1
  adjustment_type = "ChangeInCapacity"
  cooldown = 60
  autoscaling_group_name = aws_autoscaling_group.auto_scaling_group.name
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  threshold           = "5"
  period              = "300"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  alarm_description = "Scale-up if CPU > 90% for 10 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.auto_scaling_policyUp.arn}"]
  dimensions = {
    AutoScalingGroupName = "auto_scaling_group" 
    }
}

resource "aws_route53_record" "my_route53_dnsRecord" {
  zone_id = var.route_zone_id
  name = var.website
  type    = "A"
  alias {
    name                   = "${aws_lb.my-load-Balancer.dns_name}"
    zone_id                = "${aws_lb.my-load-Balancer.zone_id}"
    evaluate_target_health = true
  }

}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


resource "aws_lambda_function" "lambdaFunction" {
s3_bucket       = "codedeploy.lambda.codedeploy.mahesh"
s3_key          = "index.zip"
function_name   = "csye6225"
role            = "${aws_iam_role.CodeDeployLambdaServiceRole.arn}"
handler         = "index.handler"
runtime         = "nodejs12.x"
memory_size     = 256
timeout         = 180
reserved_concurrent_executions  = 5
environment  {
variables = {
DOMAIN_NAME = var.website
table  = "csye6225"
}
}
tags = {
Name = "Lambda Email"
}
}


resource "aws_sns_topic" "password_reset" {
name          = "password_reset"
}

resource "aws_sns_topic_subscription" "topicId" {
topic_arn       = "${aws_sns_topic.password_reset.arn}"
protocol        = "lambda"
endpoint        = "${aws_lambda_function.lambdaFunction.arn}"
}

resource "aws_lambda_permission" "lambda_permission" {
statement_id  = "AllowExecutionFromSNS"
action        = "lambda:InvokeFunction"
principal     = "sns.amazonaws.com"
source_arn    = "${aws_sns_topic.password_reset.arn}"
function_name = "${aws_lambda_function.lambdaFunction.function_name}"
}



resource "aws_iam_policy" "lambda_policy" {
name        = "lambda"
policy =  <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "LambdaDynamoDBAccess",
              "Effect": "Allow",
              "Action": ["dynamodb:*"],
              "Resource": "arn:aws:dynamodb:${var.aws_region}:${local.current_account_id}:table/dynamo_csye6225"
            },
            {
              "Sid": "LambdaSESAccess",
              "Effect": "Allow",
              "Action": ["ses:*"],
              "Resource": "arn:aws:ses:${var.aws_region}:${local.current_account_id}:identity/*"
            },
            {
              "Sid": "LambdaS3Access",
              "Effect": "Allow",
              "Action": ["s3:*"],
              "Resource": "arn:aws:s3:::codedeploy.lambda.codedeploy.mahesh/*"
            },
            {
              "Sid": "LambdaSNSAccess",
              "Effect": "Allow",
              "Action": ["sns:*"],
              "Resource": "${aws_sns_topic.password_reset.arn}"
            }
          ]
        }
EOF
}


resource "aws_iam_policy" "topic_policy" {
name        = "Topic"
description = ""
policy      = <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "AllowEC2ToPublishToSNSTopic",
              "Effect": "Allow",
              "Action": ["sns:Publish",
              "sns:CreateTopic"],
              "Resource": "${aws_sns_topic.password_reset.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_predefinedrole" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_role" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
policy_arn = "${aws_iam_policy.lambda_policy.arn}"
}

resource "aws_iam_role_policy_attachment" "topic_policy_attach_role" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
policy_arn = "${aws_iam_policy.topic_policy.arn}"
}