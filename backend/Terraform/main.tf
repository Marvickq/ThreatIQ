# ThreatIQ on AWS: ECS Fargate (api, worker, scheduler, web) behind an ALB, RDS PostgreSQL,
# ElastiCache Redis, and a private S3 artifact bucket.
#
# STATUS: statically validated only (`terraform validate`). It has NOT been planned or applied against a
# real AWS account. Review `terraform plan` carefully before applying. See docs/deployment.md.

locals {
  db_name     = "threatiq"
  db_username = "threatiq"

  # Secrets generated and stored by this module (values live in Terraform state; use an encrypted remote backend).
  generated_secrets = {
    DATABASE_URL      = aws_secretsmanager_secret.database_url.arn
    REDIS_URL         = aws_secretsmanager_secret.redis_url.arn
    CELERY_BROKER_URL = aws_secretsmanager_secret.celery_broker_url.arn
    SECRET_KEY        = aws_secretsmanager_secret.app_secret.arn
  }

  # Secrets you created yourself; included only when an ARN is supplied.
  optional_secrets = {
    for k, v in {
      NEBIUS_API_KEY      = var.nebius_api_key_secret_arn
      VIRUSTOTAL_API_KEY  = var.virustotal_api_key_secret_arn
      NVD_API_KEY         = var.nvd_api_key_secret_arn
      NVIDIA_API_KEY      = var.nvidia_api_key_secret_arn
      ENTRA_CLIENT_SECRET = var.entra_client_secret_secret_arn
    } : k => v if v != null
  }

  all_secrets       = merge(local.generated_secrets, local.optional_secrets)
  secret_arns       = values(local.all_secrets)
  container_secrets = [for k, v in local.all_secrets : { name = k, valueFrom = v }]

  entra_environment = var.entra_client_id == "" ? {} : {
    ENTRA_CLIENT_ID    = var.entra_client_id
    ENTRA_TENANT_ID    = var.entra_tenant_id
    ENTRA_REDIRECT_URI = var.entra_redirect_uri
    ENTRA_MULTI_TENANT = tostring(var.entra_multi_tenant)
  }

  # Keys defined here win over var.extra_environment.
  environment = [for k, v in merge(var.extra_environment, local.entra_environment, {
    APP_ENV                             = "production"
    FRONTEND_ORIGIN                     = var.public_url
    S3_BUCKET                           = aws_s3_bucket.artifacts.bucket
    S3_REGION                           = var.region
    NEBIUS_MODEL                        = var.nebius_model
    NEBIUS_BASE_URL                     = var.nebius_base_url
    ALLOW_DEMO_DATA                     = "false"
    ALLOW_PRIVATE_INTEGRATION_ENDPOINTS = tostring(var.allow_private_integration_endpoints)
    SCHEDULER_ENABLED                   = tostring(!var.dedicated_scheduler)
  }) : { name = k, value = v }]
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

resource "aws_secretsmanager_secret" "database_url" {
  name = "${var.name}/database-url"
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = "postgresql+psycopg://${local.db_username}:${random_password.db.result}@${aws_db_instance.this.address}:5432/${local.db_name}?sslmode=require"
}

resource "aws_secretsmanager_secret" "redis_url" {
  name = "${var.name}/redis-url"
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id     = aws_secretsmanager_secret.redis_url.id
  secret_string = "rediss://:${random_password.redis.result}@${aws_elasticache_replication_group.this.primary_endpoint_address}:6379/0"
}

# Celery requires an explicit certificate policy on rediss:// broker URLs.
resource "aws_secretsmanager_secret" "celery_broker_url" {
  name = "${var.name}/celery-broker-url"
}

resource "aws_secretsmanager_secret_version" "celery_broker_url" {
  secret_id     = aws_secretsmanager_secret.celery_broker_url.id
  secret_string = "rediss://:${random_password.redis.result}@${aws_elasticache_replication_group.this.primary_endpoint_address}:6379/0?ssl_cert_reqs=CERT_REQUIRED"
}

resource "aws_secretsmanager_secret" "app_secret" {
  name = "${var.name}/secret-key"
}

resource "aws_secretsmanager_secret_version" "app_secret" {
  secret_id     = aws_secretsmanager_secret.app_secret.id
  secret_string = random_password.app_secret.result
}

# ------------------------------------------------------------------------------------ network security
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "ThreatIQ ALB"
  vpc_id      = var.vpc_id

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "app" {
  name_prefix = "${var.name}-app-"
  description = "ThreatIQ ECS tasks"
  vpc_id      = var.vpc_id

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "data" {
  name_prefix = "${var.name}-data-"
  description = "ThreatIQ RDS and ElastiCache"
  vpc_id      = var.vpc_id

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_redirect" {
  for_each          = toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "Redirects to HTTPS only"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "alb_to_api" {
  security_group_id            = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_egress_rule" "alb_to_web" {
  security_group_id            = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "app_api_from_alb" {
  security_group_id            = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_ingress_rule" "app_web_from_alb" {
  security_group_id            = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  referenced_security_group_id = aws_security_group.alb.id
}

# Providers (Nebius, NVD, CISA, VirusTotal, Entra) and customer SIEMs are reached over the internet or private
# links; restrict with a NAT/egress firewall if your policy requires it.
resource "aws_vpc_security_group_egress_rule" "app_all" {
  security_group_id = aws_security_group.app.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "data_postgres_from_app" {
  security_group_id            = aws_security_group.data.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "data_redis_from_app" {
  security_group_id            = aws_security_group.data.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.app.id
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
  allocated_storage            = var.db_allocated_storage
  max_allocated_storage        = var.db_max_allocated_storage
  storage_type                 = "gp3"
  storage_encrypted            = true
  db_name                      = local.db_name
  username                     = local.db_username
  password                     = random_password.db.result
  db_subnet_group_name         = aws_db_subnet_group.this.name
  vpc_security_group_ids       = [aws_security_group.data.id]
  multi_az                     = var.db_multi_az
  backup_retention_period      = var.db_backup_retention_days
  copy_tags_to_snapshot        = true
  deletion_protection          = var.db_deletion_protection
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.name}-final"
  performance_insights_enabled = var.db_performance_insights_enabled
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
  num_cache_clusters         = var.redis_num_cache_clusters
  automatic_failover_enabled = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis.result
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.data.id]
}

# ------------------------------------------------------------------------------------ artifact bucket
resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.name}-artifacts-"
  force_destroy = var.artifact_bucket_force_destroy
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

# The application uploads with ServerSideEncryption="AES256" (backend/app/storage.py).
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-noncurrent-and-abort-multipart"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.artifact_noncurrent_version_expiration_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

data "aws_iam_policy_document" "artifacts_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket     = aws_s3_bucket.artifacts.id
  policy     = data.aws_iam_policy_document.artifacts_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.artifacts]
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

# Execution role: lets ECS pull images, write logs and inject exactly the listed secrets.
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

# Task role: what the application code itself may do. Only object read/write under the artifact prefix.
resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "task_s3" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "${aws_s3_bucket.artifacts.arn}/artifacts/*" # matches the default S3_PREFIX
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

resource "aws_cloudwatch_log_group" "scheduler" {
  count             = var.dedicated_scheduler ? 1 : 0
  name              = "/${var.name}/scheduler"
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
    environment  = local.environment
    secrets      = local.container_secrets
    stopTimeout  = 40
    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=3)\""]
      interval    = 15
      timeout     = 5
      retries     = 4
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.api.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "api"
      }
    }
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
    environment = local.environment
    secrets     = local.container_secrets
    stopTimeout = 60
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.worker.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "worker"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "scheduler" {
  count                    = var.dedicated_scheduler ? 1 : 0
  family                   = "${var.name}-scheduler"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions = jsonencode([{
    name        = "scheduler"
    image       = var.api_image
    essential   = true
    command     = ["python", "-m", "app.scheduler"]
    environment = local.environment
    secrets     = local.container_secrets
    stopTimeout = 40
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.scheduler[0].name
        awslogs-region        = var.region
        awslogs-stream-prefix = "scheduler"
      }
    }
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
    # The ALB routes /api/* straight to the api service; nginx only proxies as a fallback.
    environment = [{ name = "BACKEND_URL", value = "http://127.0.0.1:8000" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.web.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "web"
      }
    }
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
  enable_deletion_protection = var.alb_deletion_protection
}

resource "aws_lb_target_group" "api" {
  name_prefix = "api-"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path    = "/api/v1/ready"
    matcher = "200"
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_lb_target_group" "web" {
  name_prefix = "web-"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path    = "/healthz"
    matcher = "200"
  }

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

  health_check_grace_period_seconds = 60

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

# Exactly one scheduler: stop the old task before starting the new one so polling is never duplicated.
resource "aws_ecs_service" "scheduler" {
  count                              = var.dedicated_scheduler ? 1 : 0
  name                               = "${var.name}-scheduler"
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.scheduler[0].arn
  desired_count                      = 1
  launch_type                        = "FARGATE"
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

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
  desired_count   = var.web_desired_count
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
