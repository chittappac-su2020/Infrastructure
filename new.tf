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

resource "aws_instance" "webinstance" {
  ami           = "ami-0c614a46ecac272cb"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.application.id]
  disable_api_termination = false
  instance_initiated_shutdown_behavior = "stop"
  subnet_id   = aws_subnet.subnet.id
  key_name = "ssh"
  
  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name = "Wep_App_Instance"
  }

  user_data = <<-EOF
                #!/bin/bash
                sudo touch userdata.sh\n
                sudo echo export RDS_USERNAME=${aws_db_instance.csye6225.name} >> userdata.sh
                sudo echo export RDS_PASSWORD=${aws_db_instance.csye6225.password} >> userdata.sh
                sudo echo export RDS_HOSTNAME=${aws_db_instance.csye6225.address} >> userdata.sh
                sudo echo export S3_BUCKET_NAME=${aws_s3_bucket.webapp.bucket} >> userdata.sh
                
  EOF
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
                "arn:aws:s3:::${aws_s3_bucket.webapp.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.webapp.bucket}/*"
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




