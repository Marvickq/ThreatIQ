# ThreatIQ on AWS: ECS Fargate (api, worker, web) behind an ALB, RDS PostgreSQL, ElastiCache Redis, S3 artifacts.
#
# STATUS: written to be applied as-is but NOT validated or applied in this repository's verification
# (Terraform and AWS were not available). Run `terraform init && terraform validate && terraform plan`
# and review the plan before applying. See docs/deployment.md.

data "aws_vpc" "this" { id = var.vpc_id }

locals {
  tags = { Project = var.name }
}

# ------------------------------------------------------------------------------------ secrets
resource "random_password" "db" {
  length  = 32
  special = false
}
resource "random_password" "redis" {
  length  = 32
  special = false
}
resource "random_password" "app_secret" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "database_url" { name = "${var.name}/database-url" }
resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = "postgresql+psycopg://threatiq:${random_password.db.result}@${aws_db_instance.this.address}:5432/threatiq?sslmode=require"
}
resource "aws_secretsmanager_secret" "redis_url" { name = "${var.name}/redis-url" }
resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id     = aws_secretsmanager_secret.redis_url.id
  secret_string = "rediss://:${random_password.redis.result}@${aws_elasticache_replication_group.this.primary_endpoint_address}:6379/0"
}
resource "aws_secretsmanager_secret" "app_secret" { name = "${var.name}/secret-key" }
resource "aws_secretsmanager_secret_version" "app_secret" {
  secret_id     = aws_secretsmanager_secret.app_secret.id
  secret_string = random_password.app_secret.result
}

# ------------------------------------------------------------------------------------ network security
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # redirects to HTTPS only
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "app" {
  name_prefix = "${var.name}-app-"
  vpc_id      = var.vpc_id
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # providers (Nebius, NVD, CISA) and SIEMs; restrict with a NAT/egress firewall if required
  }
}
resource "aws_security_group" "data" {
  name_prefix = "${var.name}-data-"
  vpc_id      = var.vpc_id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

# ------------------------------------------------------------------------------------ data stores
resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
}
resource "aws_db_instance" "this" {
  identifier                   = var.name
  engine                       = "postgres"
  engine_version               = "16"
  instance_class               = var.db_instance_class
  allocated_storage            = 50
  max_allocated_storage        = 500
  storage_type                 = "gp3"
  storage_encrypted            = true
  db_name                      = "threatiq"
  username                     = "threatiq"
  password                     = random_password.db.result
  db_subnet_group_name         = aws_db_subnet_group.this.name
  vpc_security_group_ids       = [aws_security_group.data.id]
  multi_az                     = var.db_multi_az
  backup_retention_period      = 14
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.name}-final"
  performance_insights_enabled = true
  publicly_accessible          = false
  auto_minor_version_upgrade   = true
}

resource "aws_elasticache_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
}
resource "aws_elasticache_replication_group" "this" {
  replication_group_id       = var.name
  description                = "ThreatIQ transient cache, rate limits, pub/sub and Celery broker (never a source of truth)"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis.result
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.data.id]
}

resource "aws_s3_bucket" "artifacts" { bucket_prefix = "${var.name}-artifacts-" }
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

# ------------------------------------------------------------------------------------ IAM
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}
locals {
  secret_arns = compact([
    aws_secretsmanager_secret.database_url.arn, aws_secretsmanager_secret.redis_url.arn, aws_secretsmanager_secret.app_secret.arn,
    var.nebius_api_key_secret_arn, var.virustotal_api_key_secret_arn, var.nvd_api_key_secret_arn,
  ])
}
resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}
resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy" "execution_secrets" {
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = local.secret_arns }]
  })
}
resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}
resource "aws_iam_role_policy" "task_s3" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ # least privilege: only this bucket's artifact prefix, only object read/write
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "${aws_s3_bucket.artifacts.arn}/artifacts/*"
    }]
  })
}

# ------------------------------------------------------------------------------------ logs + cluster
resource "aws_cloudwatch_log_group" "api" {
  name              = "/${var.name}/api"
  retention_in_days = var.log_retention_days
}
resource "aws_cloudwatch_log_group" "worker" {
  name              = "/${var.name}/worker"
  retention_in_days = var.log_retention_days
}
resource "aws_cloudwatch_log_group" "web" {
  name              = "/${var.name}/web"
  retention_in_days = var.log_retention_days
}
resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  base_env = [
    { name = "APP_ENV", value = "production" },
    { name = "FRONTEND_ORIGIN", value = var.public_url },
    { name = "S3_BUCKET", value = aws_s3_bucket.artifacts.bucket },
    { name = "S3_REGION", value = var.region },
    { name = "NEBIUS_MODEL", value = var.nebius_model },
    { name = "NEBIUS_BASE_URL", value = "https://api.tokenfactory.nebius.com/v1" },
    { name = "ALLOW_DEMO_DATA", value = "false" },
    { name = "ALLOW_PRIVATE_INTEGRATION_ENDPOINTS", value = tostring(var.allow_private_integration_endpoints) },
    { name = "CELERY_BROKER_URL", value = "" }, # set below from the Redis secret
  ]
  base_secrets = concat(
    [
      { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
      { name = "REDIS_URL", valueFrom = aws_secretsmanager_secret.redis_url.arn },
      { name = "CELERY_BROKER_URL", valueFrom = aws_secretsmanager_secret.redis_url.arn },
      { name = "SECRET_KEY", valueFrom = aws_secretsmanager_secret.app_secret.arn },
    ],
    var.nebius_api_key_secret_arn == null ? [] : [{ name = "NEBIUS_API_KEY", valueFrom = var.nebius_api_key_secret_arn }],
    var.virustotal_api_key_secret_arn == null ? [] : [{ name = "VIRUSTOTAL_API_KEY", valueFrom = var.virustotal_api_key_secret_arn }],
    var.nvd_api_key_secret_arn == null ? [] : [{ name = "NVD_API_KEY", valueFrom = var.nvd_api_key_secret_arn }],
  )
  # CELERY_BROKER_URL comes from the secret, so drop the empty placeholder from plain env.
  plain_env = [for e in local.base_env : e if e.name != "CELERY_BROKER_URL"]
}

# ------------------------------------------------------------------------------------ task definitions
resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions = jsonencode([{
    name         = "api"
    image        = var.api_image
    essential    = true
    portMappings = [{ containerPort = 8000 }]
    environment  = local.plain_env
    secrets      = local.base_secrets
    stopTimeout  = 40
    healthCheck  = { command = ["CMD-SHELL", "python -c \"import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=3)\""], interval = 15, timeout = 5, retries = 4, startPeriod = 30 }
    logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.api.name, awslogs-region = var.region, awslogs-stream-prefix = "api" } }
  }])
}
resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions = jsonencode([{
    name        = "worker"
    image       = var.api_image
    essential   = true
    command     = ["celery", "-A", "app.worker.celery_app", "worker", "--loglevel=INFO", "--concurrency=2"]
    environment = local.plain_env
    secrets     = local.base_secrets
    stopTimeout = 60
    logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.worker.name, awslogs-region = var.region, awslogs-stream-prefix = "worker" } }
  }])
}
resource "aws_ecs_task_definition" "web" {
  family                   = "${var.name}-web"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  container_definitions = jsonencode([{
    name         = "web"
    image        = var.frontend_image
    essential    = true
    portMappings = [{ containerPort = 80 }]
    # Same-host routing at the ALB sends /api/* straight to the api service; nginx still proxies as a fallback.
    environment = [{ name = "BACKEND_URL", value = "http://127.0.0.1:8000" }]
    logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.web.name, awslogs-region = var.region, awslogs-stream-prefix = "web" } }
  }])
}

# ------------------------------------------------------------------------------------ load balancer
resource "aws_lb" "this" {
  name                       = var.name
  load_balancer_type         = "application"
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  idle_timeout               = 300 # live-event streams send a heartbeat every 15s
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}
resource "aws_lb_target_group" "api" {
  name_prefix = "api-"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check { path = "/api/v1/ready" }
  lifecycle { create_before_destroy = true }
}
resource "aws_lb_target_group" "web" {
  name_prefix = "web-"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check { path = "/healthz" }
  lifecycle { create_before_destroy = true }
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
  condition {
    path_pattern { values = ["/api/*"] }
  }
}

# ------------------------------------------------------------------------------------ services
resource "aws_ecs_service" "api" {
  name            = "${var.name}-api"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"
  deployment_circuit_breaker {
    enable   = true
    rollback = true # automatic rollback of a failed deployment
  }
  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.app.id]
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener_rule.api]
}
resource "aws_ecs_service" "worker" {
  name            = "${var.name}-worker"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.app.id]
  }
}
resource "aws_ecs_service" "web" {
  name            = "${var.name}-web"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.web.arn
  desired_count   = 2
  launch_type     = "FARGATE"
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.app.id]
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.web.arn
    container_name   = "web"
    container_port   = 80
  }
  depends_on = [aws_lb_listener.https]
}
