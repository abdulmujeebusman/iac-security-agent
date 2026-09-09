# Deliberately insecure Terraform for the demo.

resource "aws_s3_bucket" "demo" {
  bucket = "demo-insecure-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket                  = aws_s3_bucket.demo.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "web" {
  name = "demo-web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin_like" {
  name = "demo-wildcard-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

variable "database_password" {
  default = "SuperSecretPassword123"
}

resource "aws_s3_bucket" "logs" {
  bucket = "another-bucket-without-logging"
}
