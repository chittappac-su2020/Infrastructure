variable "aws_region"{
    type = string
    default = "us-east-1"
}

variable "vpc_cidr"{
    type = string
    default = "10.0.0.0/16"
}

variable "subnet_cidr"{
    type = string
    default = "10.0.1.0/24"
}

variable "subnet2_cidr"{
    type = string
    default = "10.0.2.0/24"
}

variable "subnet3_cidr"{
    type = string
    default = "10.0.3.0/24"
}

variable "route_cidr"{
    type = string
    default = "0.0.0.0/0"
}

variable "subnet_availzone"{
    type = string
    default = "us-east-1a"
}

variable "subnet2_availzone"{
    type = string
    default = "us-east-1b"
}

variable "subnet3_availzone"{
    type = string
    default = "us-east-1c"
}

variable "s3_bucket_name"{
    type = string
    default = "webapp"
}

variable "key_name"{
    type = string
    default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC52lyxcptCUIAinfU/C7zEWWRt7e2GjPXyYyfV9Lp1OrXkNDqe7Yj3btvNLcl8AZpx/HQTw+CTflsF1wCTRicMSvActwJ5ZQpKyhU43ohcXd+ZmQx9t9O84ZZ88eunuY3UbqgGkC+hwHnhjGNSQg2S7X4tm9Ay6ZmIE8MgJKCXwLsxIvTl5CJP9VdePsbLwj5FDjv4xq/NAl5xuZnwMEwrBkmMuf+O7wtOT/zblK8anPRTok8Gxb5MbqUIPh7dhuK4v8upIVcKLI+aqxPLunSFsk3tZBkFS05IHiC7Qy3cCxZq1Cy+kKTK7crbDjaame4OPARl6bGDpcxPtItZSUAb apple@Apples-MacBook-Pro.local"
}

variable "dname"{
    type = string
    default = "chandrakanthchittappa.site.tld"
}

variable "AMIid"{
    type = string
}

variable "keyname"{
    type = string
    default = "ssh"
}

variable "instance_name"{
    type = string
    default = "webapp"
}

variable "zone_id"{
    type = string
    default = "Z0259833JNL84YV5YUYU"
}

variable "csye_dns_name"{
    type = string
    default = "prod.chandrakanthchittappa.site"
}

variable "codedeploy_lambda_s3_bucket"{
    type = string 
    default = "codedeploy.lambda.service"
}
