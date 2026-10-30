output "alb_dns_name" {
  description = "Point your DNS record (CNAME/ALIAS) for public_url at this."
  value       = aws_lb.this.dns_name
}
output "artifact_bucket" { value = aws_s3_bucket.artifacts.bucket }
output "database_endpoint" { value = aws_db_instance.this.address }
output "cluster_name" { value = aws_ecs_cluster.this.name }
