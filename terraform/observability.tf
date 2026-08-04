# -----------------------------------------------------------------------------
# CloudWatch Metric Alarms (p95 Latency & 5xx Error Triggers)
# -----------------------------------------------------------------------------

# Alarm 1: Trigger if p95 Latency exceeds 500ms over 5 minutes
resource "aws_cloudwatch_metric_alarm" "high_latency_alarm" {
  alarm_name          = "zero-trust-evaluator-high-p95-latency-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  extended_statistic  = "p95"
  threshold           = 500
  alarm_description   = "Alarm triggers when Zero-Trust evaluator p95 latency exceeds 500ms"

  dimensions = {
    FunctionName = aws_lambda_function.evaluator_lambda.function_name
  }
}

# Alarm 2: Trigger if 5xx Server Error count is greater than 1
resource "aws_cloudwatch_metric_alarm" "server_error_alarm" {
  alarm_name          = "zero-trust-evaluator-5xx-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggers when evaluator throws unhandled execution errors"

  dimensions = {
    FunctionName = aws_lambda_function.evaluator_lambda.function_name
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Real-Time Performance Dashboard
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "evaluator_dashboard" {
  dashboard_name = "ZeroTrust-Evaluator-Observability-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.evaluator_lambda.function_name],
            [".", "Errors", ".", "."],
            [".", "Throttles", ".", "."]
          ]
          period = 60
          stat   = "Sum"
          region = var.aws_region
          title  = "Throughput, Errors & Throttles"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.evaluator_lambda.function_name, { stat = "p50" }],
            ["...", { stat = "p90" }],
            ["...", { stat = "p95" }]
          ]
          period = 60
          region = var.aws_region
          title  = "Execution Latency Percentiles (p50, p90, p95)"
        }
      }
    ]
  })
}