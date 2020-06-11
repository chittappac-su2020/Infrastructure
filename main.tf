provider "aws" {
    region = "us-east-1"
}

variable "newTag" {
    type = "string"
}


resource "aws_vpc" "csye6225_demo_vpc" {
    cidr_block = "10.0.0.0/16"
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
    cidr_block = "10.0.1.0/24"
    vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
    availability_zone = "us-east-1a"
    map_public_ip_on_launch = true

    tags = {
        Name = "csye6225-subnet",
        Tag2 = "${var.newTag}"
    }
}

resource "aws_subnet" "subnet2" {
    cidr_block = "10.0.2.0/24"
    vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
    availability_zone = "us-east-1b"
    map_public_ip_on_launch = true

    tags = {
        Name = "csye6225-subnet",
        Tag2 = "${var.newTag}"
    }
}

resource "aws_subnet" "subnet3" {
    cidr_block = "10.0.3.0/24"
    vpc_id = "${aws_vpc.csye6225_demo_vpc.id}"
    availability_zone = "us-east-1c"
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
      cidr_block = "0.0.0.0/0"
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










