terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  backend "s3" {
    bucket         = "zero-trust-tfstate-244206439037"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
  }
}

# -----------------------------------------------------------------------------
# 1. Archive Source Code Package
# -----------------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/lambda.zip"
}

# -----------------------------------------------------------------------------
# 2. CloudWatch Log Groups (7-Day Retention)
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/zero-trust-evaluator-${var.environment}"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "invalidator_logs" {
  name              = "/aws/lambda/zero-trust-invalidator-${var.environment}"
  retention_in_days = 7
}

# -----------------------------------------------------------------------------
# 3. DynamoDB Table (Streams Enabled for Real-Time Cache Invalidation)
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Global Active-Active DynamoDB Replica Table
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "rbac_store" {
  name             = "zero-trust-rbac-store-${var.environment}"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "PK"
  range_key        = "SK"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # Multi-Region Replication Target
  replica {
    region_name = "eu-west-1"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = var.environment
    Service     = "ZeroTrustEvaluator"
  }
}

# -----------------------------------------------------------------------------
# 4. IAM Roles & Scoped Least-Privilege Policies
# -----------------------------------------------------------------------------

# --- Evaluator Lambda IAM ---
resource "aws_iam_role" "lambda_role" {
  name = "zero-trust-lambda-exec-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "zero-trust-lambda-policy-${var.environment}"
  description = "Scoped permissions for Zero Trust Evaluator and Admin Lambdas"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = [
          aws_dynamodb_table.rbac_store.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# --- Invalidator Lambda IAM ---
resource "aws_iam_role" "invalidator_role" {
  name = "zero-trust-invalidator-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "invalidator_policy" {
  name        = "zero-trust-invalidator-policy-${var.environment}"
  description = "Permissions for DynamoDB Stream Cache Invalidator Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.invalidator_logs.arn}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream",
          "dynamodb:ListStreams"
        ]
        Resource = [
          "${aws_dynamodb_table.rbac_store.arn}/stream/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          aws_dynamodb_table.rbac_store.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "invalidator_attach" {
  role       = aws_iam_role.invalidator_role.name
  policy_arn = aws_iam_policy.invalidator_policy.arn
}

# -----------------------------------------------------------------------------
# 5. Lambda Functions
# -----------------------------------------------------------------------------

# --- Access Evaluator Engine ---
resource "aws_lambda_function" "evaluator_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "zero-trust-evaluator-${var.environment}"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  memory_size      = 256
  timeout          = 10

  environment {
    variables = {
      DYNAMODB_TABLE    = aws_dynamodb_table.rbac_store.name
      ENVIRONMENT       = var.environment
      CACHE_TTL_SECONDS = "300"
      ALLOWED_SUBNETS   = jsonencode(["10.0.0.0/16", "192.168.1.0/24"])
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy_attachment.lambda_attach
  ]
}

# --- Stream Cache Invalidator ---
resource "aws_lambda_function" "invalidator_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "zero-trust-invalidator-${var.environment}"
  role             = aws_iam_role.invalidator_role.arn
  handler          = "invalidator.lambda_handler"
  runtime          = "python3.12"
  memory_size      = 128
  timeout          = 10

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.rbac_store.name
      ENVIRONMENT    = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.invalidator_logs,
    aws_iam_role_policy_attachment.invalidator_attach
  ]
}

# -----------------------------------------------------------------------------
# 6. Event Source Mapping (DynamoDB Stream -> Invalidator Lambda)
# -----------------------------------------------------------------------------
resource "aws_lambda_event_source_mapping" "dynamodb_stream_trigger" {
  event_source_arn  = aws_dynamodb_table.rbac_store.stream_arn
  function_name     = aws_lambda_function.invalidator_lambda.arn
  starting_position = "LATEST"
  batch_size        = 10
}

# -----------------------------------------------------------------------------
# 7. API Gateway HTTP API (v2) Setup
# -----------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "http_api" {
  name          = "zero-trust-api-${var.environment}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "default_stage" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.evaluator_lambda.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "evaluate_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /evaluate"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_lambda_permission" "api_gw_permission" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evaluator_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# -----------------------------------------------------------------------------
# 8. Output Definition
# -----------------------------------------------------------------------------
output "api_endpoint" {
  value       = "${aws_apigatewayv2_api.http_api.api_endpoint}/evaluate"
  description = "HTTP API Gateway endpoint for access evaluations"
}

# -----------------------------------------------------------------------------
# Admin API Lambda & Permissions
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "admin_logs" {
  name              = "/aws/lambda/zero-trust-admin-${var.environment}"
  retention_in_days = 7
}

resource "aws_lambda_function" "admin_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "zero-trust-admin-${var.environment}"
  role             = aws_iam_role.lambda_role.arn
  handler          = "admin_handler.lambda_handler"
  runtime          = "python3.12"
  memory_size      = 128
  timeout          = 10

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.rbac_store.name
      ENVIRONMENT    = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.admin_logs,
    aws_iam_role_policy_attachment.lambda_attach
  ]
}

resource "aws_lambda_permission" "admin_api_permission" {
  statement_id  = "AllowAdminExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.admin_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# -----------------------------------------------------------------------------
# Admin HTTP API Integrations & Routes
# -----------------------------------------------------------------------------
resource "aws_apigatewayv2_integration" "admin_lambda_integration" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.admin_lambda.invoke_arn
  payload_format_version = "2.0"
}

# GET /admin/roles
resource "aws_apigatewayv2_route" "get_roles_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "GET /admin/roles"
  target    = "integrations/${aws_apigatewayv2_integration.admin_lambda_integration.id}"
}

# POST /admin/roles
resource "aws_apigatewayv2_route" "post_roles_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /admin/roles"
  target    = "integrations/${aws_apigatewayv2_integration.admin_lambda_integration.id}"
}

# DELETE /admin/roles/{role_name}
resource "aws_apigatewayv2_route" "delete_roles_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "DELETE /admin/roles/{role_name}"
  target    = "integrations/${aws_apigatewayv2_integration.admin_lambda_integration.id}"
}