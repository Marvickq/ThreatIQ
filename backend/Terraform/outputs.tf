output "alb_dns_name" {
  description = "Point your DNS record (CNAME/ALIAS) for public_url at this."
  value       = aws_lb.this.dns_name
}

output "artifact_bucket" {
  description = "S3 bucket for large evidence/raw-event artifacts (S3_BUCKET)."
  value       = aws_s3_bucket.artifacts.bucket
}

output "database_endpoint" {
  description = "RDS PostgreSQL address (not publicly accessible)."
  value       = aws_db_instance.this.address
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "task_role_arn" {
  description = "IAM role assumed by the api, worker and scheduler containers."
  value       = aws_iam_role.task.arn
}

output "app_security_group_id" {
  description = "Security group of the ECS tasks."
  value       = aws_security_group.app.id
}
