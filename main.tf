provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

resource "google_compute_network" "custom_vpc_network" {
  for_each                        = var.vpc_names
  name                            = each.value.name
  auto_create_subnetworks         = each.value.auto_create_subnetworks
  routing_mode                    = each.value.routing_mode
  delete_default_routes_on_create = each.value.delete_default_routes_on_create
}

resource "google_compute_subnetwork" "subnetworks" {
  for_each                 = var.subnet_list
  name                     = each.value.name
  ip_cidr_range            = each.value.ip_cidr_range
  network                  = google_compute_network.custom_vpc_network[each.value.network].self_link
  private_ip_google_access = each.value.private_ip_google_access
}

resource "google_compute_route" "custom-vpc-1" {
  name             = "custom-vpc-1-route"
  dest_range       = "0.0.0.0/0"
  network          = google_compute_network.custom_vpc_network["custom-vpc-1"].self_link
  next_hop_gateway = "default-internet-gateway"
}


data "google_compute_image" "latest_image" {
  project = var.project
  family  = "custom-centos-8"
}

resource "google_service_account" "webapp-service-account" {
  account_id                   = var.webapp_service_account_id
  display_name                 = var.service_account_display_name
  create_ignore_already_exists = true
}

resource "google_project_iam_binding" "logging_admin" {
  project = var.project
  role    = var.admin_role

  members = ["serviceAccount:${google_service_account.webapp-service-account.email}"]
}

resource "google_project_iam_binding" "monitoring_metric_writer" {
  project = var.project
  role    = var.metricWriter_role

  members = ["serviceAccount:${google_service_account.webapp-service-account.email}"]
}

resource "google_project_iam_binding" "token_creator" {
  project = var.project
  role    = var.token_creator_role

  members = ["serviceAccount:${google_service_account.webapp-service-account.email}"]
}

resource "google_compute_firewall" "custom_deny_firewall_rule" {
  for_each = var.vpc_names

  name     = "custom-deny-firewall-rule"
  network  = google_compute_network.custom_vpc_network[each.value.name].self_link
  priority = 1500

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  target_tags = ["deny-rule"]
}
resource "google_compute_firewall" "custom_allow_firewall_rule" {
  for_each = var.vpc_names

  name     = "custom-allow-firewall-rule"
  network  = google_compute_network.custom_vpc_network[each.value.name].self_link
  priority = 1300

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]

  target_tags = ["allow-rule"]
}

resource "google_project_service" "project" {
  project            = var.project
  service            = "servicenetworking.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_global_address" "private_ip" {
  provider      = google-beta
  project       = var.project
  name          = var.private_ip_name
  address_type  = var.private_ip_addressType
  purpose       = var.private_ip_purpose
  prefix_length = 24
  network       = google_compute_network.custom_vpc_network["custom-vpc-1"].self_link
}
resource "google_service_networking_connection" "private_vpc_connection" {
  provider = google-beta

  network                 = google_compute_network.custom_vpc_network["custom-vpc-1"].self_link
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip.name]
}

resource "random_id" "db_name_suffix" {
  byte_length = 4
}

resource "random_password" "random_user_password" {
  length  = 16
  special = false
}

resource "google_sql_database_instance" "mysql_instance" {
  provider = google-beta

  name             = "private-instance-${random_id.db_name_suffix.hex}"
  project          = var.project
  region           = var.region
  database_version = var.database_version

  encryption_key_name = google_kms_crypto_key.sql_crypto_key.id

  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier = "db-n1-standard-1"

    availability_type = var.availability_type
    disk_type         = "pd-ssd"
    disk_size         = 100

    ip_configuration {
      ipv4_enabled                                  = var.ipv4_enabled
      private_network                               = google_compute_network.custom_vpc_network["custom-vpc-1"].self_link
      enable_private_path_for_google_cloud_services = true
    }
    backup_configuration {
      enabled            = true
      binary_log_enabled = true
    }
  }

  deletion_protection = var.deletion_protection
}

resource "google_sql_database" "my_sqldatabase" {
  name     = var.db_name
  instance = google_sql_database_instance.mysql_instance.name
}

resource "google_sql_user" "my_sql_user" {
  name     = var.sql_username
  instance = google_sql_database_instance.mysql_instance.name
  password = random_password.random_user_password.result
}

data "google_dns_managed_zone" "my-zone" {
  name = var.zone_name
}

resource "google_vpc_access_connector" "custom_vpc_connector" {
  name          = var.vpc_connector_name
  ip_cidr_range = var.vpc_connector_cidr
  network       = google_compute_network.custom_vpc_network["custom-vpc-1"].self_link
  machine_type  = var.vpc_connector_machine_type
}


resource "google_pubsub_topic" "custom_pubsub_topic" {
  name                       = var.pubsub_topic_name
  message_retention_duration = "604800s"
}

resource "google_pubsub_topic_iam_binding" "pubsub_editor" {
  topic = google_pubsub_topic.custom_pubsub_topic.name
  role  = var.pubsub_topic_role

  members = ["serviceAccount:${google_service_account.webapp-service-account.email}"]
}

resource "google_pubsub_subscription" "custom_pubsub_subscription" {
  name  = var.pubsub_subscription_name
  topic = google_pubsub_topic.custom_pubsub_topic.id

  message_retention_duration = "604800s"
  retain_acked_messages      = true

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  enable_exactly_once_delivery = true
  enable_message_ordering      = true
}

resource "google_pubsub_subscription_iam_binding" "editor" {
  subscription = google_pubsub_subscription.custom_pubsub_subscription.name
  role         = var.pubsub_subscription_role

  members = ["serviceAccount:${google_service_account.webapp-service-account.email}"]
}

resource "google_storage_bucket" "custom_cloudfunction_bucket" {
  name     = var.cloudfunction_bucket_name
  location = var.region
  # uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.cloud_bucket_crypto_key.id
  }

  depends_on = [google_kms_crypto_key_iam_binding.bucket_crypto_key_iam]
}

resource "google_storage_bucket_object" "custom_bucket_object" {
  name   = var.cloudfunction_bucket_object_name
  bucket = google_storage_bucket.custom_cloudfunction_bucket.name
  source = "cloud-function.zip"
}

resource "google_cloudfunctions2_function" "custom_cloud_function" {
  name     = var.cloudfunction_name
  location = var.region

  build_config {
    runtime     = "nodejs20"
    entry_point = "webappFunction"
    source {
      storage_source {
        bucket = google_storage_bucket.custom_cloudfunction_bucket.name
        object = google_storage_bucket_object.custom_bucket_object.name
      }
    }
  }

  service_config {
    available_memory                 = "128Mi"
    timeout_seconds                  = 120
    max_instance_request_concurrency = 1
    available_cpu                    = "1"
    environment_variables = {
      API_KEY           = var.cloudfunction_env_api_key
      DOMAIN            = var.cloudfunction_env_domain
      HOST              = google_sql_database_instance.mysql_instance.private_ip_address
      DATABASE_NAME     = var.db_name
      DATABASE_USER     = google_sql_user.my_sql_user.name
      DATABASE_PASSWORD = google_sql_user.my_sql_user.password
    }

    vpc_connector                  = google_vpc_access_connector.custom_vpc_connector.name
    vpc_connector_egress_settings  = "PRIVATE_RANGES_ONLY"
    all_traffic_on_latest_revision = true
    service_account_email          = google_service_account.cloudfunction_service_account.email
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = var.cloudfunction_event_type
    pubsub_topic          = google_pubsub_topic.custom_pubsub_topic.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.cloudfunction_service_account.email
  }
}

resource "google_service_account" "cloudfunction_service_account" {
  account_id                   = "cloud-service-account-id"
  display_name                 = "Cloudfunction service account"
  create_ignore_already_exists = true
}

resource "google_cloudfunctions2_function_iam_member" "invoker" {
  cloud_function = google_cloudfunctions2_function.custom_cloud_function.name
  role           = var.cloudfunction_invoker_role
  member         = "serviceAccount:${google_service_account.cloudfunction_service_account.email}"
}

resource "google_cloud_run_service_iam_member" "cloud_run_invoker" {
  service = google_cloudfunctions2_function.custom_cloud_function.name
  role    = var.cloudfunction_run_invoker_role
  member  = "serviceAccount:${google_service_account.cloudfunction_service_account.email}"
}

// Assignment - 8

resource "google_compute_region_instance_template" "webapp_instance_template" {
  name_prefix  = "webapp-instance-template-"
  machine_type = var.machine_type
  region       = var.region


  network_interface {
    network    = google_compute_network.custom_vpc_network["custom-vpc-1"].self_link
    subnetwork = google_compute_subnetwork.subnetworks["webapp-1"].self_link

    access_config {}
  }

  disk {
    source_image = data.google_compute_image.latest_image.self_link
    disk_type    = "pd-balanced"
    disk_size_gb = 100

    source_image_encryption_key {
      kms_key_service_account = data.google_storage_project_service_account.gcs_account.email_address
      kms_key_self_link       = google_kms_crypto_key.vm_crypto_key.id
    }

    disk_encryption_key {
      kms_key_self_link = google_kms_crypto_key.vm_crypto_key.id
    }
  }


  lifecycle {
    create_before_destroy = true
  }

  tags = ["allow-rule", "deny-rule"]

  metadata = {
    startup-script = <<-EOF
      #!/bin/bash

      set -e

      file_to_check="/opt/completed.txt"

      # Check if the file exists
      if [ -f "$file_to_check" ]; then
        echo "File exists. Exiting without executing further."
        exit 0
      else
        sudo echo "DATABASE_USER=${google_sql_user.my_sql_user.name}" >> /opt/webapp/.env
        sudo echo "DATABASE_PASSWORD=${google_sql_user.my_sql_user.password}" >> /opt/webapp/.env
        sudo echo "DATABASE_NAME=${var.db_name}" >> /opt/webapp/.env
        sudo echo "PORT=${var.port}" >> /opt/webapp/.env
        sudo echo "HOST=${google_sql_database_instance.mysql_instance.private_ip_address}" >> /opt/webapp/.env
        sudo echo "ENVIRONMENT=${var.environment}" >> /opt/webapp/.env
        sudo echo "PUBSUB_TOPIC=${var.pubsub_topic_name}" >> /opt/webapp/.env
        sudo echo "PUBSUB_SUBSCRIPTION=${var.pubsub_subscription_name}" >> /opt/webapp/.env
        sudo echo "DOMAIN=${var.webapp_env_domain}" >> /opt/webapp/.env

        touch /opt/completed.txt
      fi

    EOF
  }

  service_account {
    email  = google_service_account.webapp-service-account.email
    scopes = ["cloud-platform"]
  }

  depends_on = [google_kms_crypto_key_iam_binding.vm_crypto_key_iam]
}

resource "google_compute_region_autoscaler" "webapp_auto_scaler" {
  name   = "webapp-auto-scaler"
  region = var.region
  target = google_compute_region_instance_group_manager.webapp_instance_group.self_link

  autoscaling_policy {
    max_replicas = 5
    min_replicas = 3

    cpu_utilization {
      target = 0.20
    }
  }
}

resource "google_compute_region_instance_group_manager" "webapp_instance_group" {
  name = "webapp-instance-group"

  base_instance_name        = "webapp-instances"
  region                    = var.region
  distribution_policy_zones = ["us-east1-b", "us-east1-c", "us-east1-d"]

  version {
    instance_template = google_compute_region_instance_template.webapp_instance_template.id
    name              = "primary"
  }

  named_port {
    name = "http"
    port = 8080
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.mig_health_check.id
    initial_delay_sec = 300
  }
}

resource "google_compute_region_health_check" "mig_health_check" {
  name                = "autohealing-health-check"
  check_interval_sec  = 60
  timeout_sec         = 60
  healthy_threshold   = 3
  unhealthy_threshold = 3

  http_health_check {
    request_path = "/healthz"
    port         = "8080"
  }
}


module "gce-lb-http" {
  source  = "terraform-google-modules/lb-http/google"
  version = "~> 10.0"
  name    = "loadbalancer"
  project = var.project

  ssl                             = true
  managed_ssl_certificate_domains = ["ashishbadhe.me"]
  http_forward                    = false

  create_address = true

  network = google_compute_network.custom_vpc_network["custom-vpc-1"].name

  backends = {
    default = {

      protocol    = "HTTP"
      port_name   = "http"
      timeout_sec = 60
      enable_cdn  = false

      health_check = {
        request_path        = "/healthz"
        port                = 8080
        healthy_threshold   = 3
        unhealthy_threshold = 5
        logging             = true
      }

      log_config = {
        enable = true
      }

      groups = [
        {
          group = google_compute_region_instance_group_manager.webapp_instance_group.instance_group
        }
      ]

      iap_config = {
        enable = false
      }
    }
  }
}

resource "google_dns_record_set" "a" {
  name         = data.google_dns_managed_zone.my-zone.dns_name
  managed_zone = data.google_dns_managed_zone.my-zone.name
  type         = "A"
  ttl          = 300

  rrdatas = [module.gce-lb-http.external_ip]
}



// Assignment - 9
resource "google_kms_key_ring" "custom_key_ring" {
  name     = "key-ring-${random_id.db_name_suffix.hex}"
  location = var.region
}

resource "google_kms_crypto_key" "vm_crypto_key" {
  provider        = google-beta
  name            = "vm-crypto-key"
  key_ring        = google_kms_key_ring.custom_key_ring.id
  rotation_period = "2592000s"

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_crypto_key" "sql_crypto_key" {
  provider        = google-beta
  name            = "sql-crypto-key"
  key_ring        = google_kms_key_ring.custom_key_ring.id
  rotation_period = "2592000s"

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_crypto_key" "cloud_bucket_crypto_key" {
  provider        = google-beta
  name            = "cloud-bucket-crypto-key"
  key_ring        = google_kms_key_ring.custom_key_ring.id
  rotation_period = "2592000s"

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_project_service_identity" "gcp_sa_cloud_sql" {
  provider = google-beta
  project  = var.project
  service  = "sqladmin.googleapis.com"
}

resource "google_kms_crypto_key_iam_binding" "vm_crypto_key_iam" {
  provider      = google-beta
  crypto_key_id = google_kms_crypto_key.vm_crypto_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = ["serviceAccount:service-628283172311@compute-system.iam.gserviceaccount.com"]
}

resource "google_kms_crypto_key_iam_binding" "sql_crypto_key_iam" {
  provider      = google-beta
  crypto_key_id = google_kms_crypto_key.sql_crypto_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = ["serviceAccount:${google_project_service_identity.gcp_sa_cloud_sql.email}"]
}

data "google_storage_project_service_account" "gcs_account" {}

resource "google_kms_crypto_key_iam_binding" "bucket_crypto_key_iam" {
  provider      = google-beta
  crypto_key_id = google_kms_crypto_key.cloud_bucket_crypto_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = ["serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"]
}

resource "google_secret_manager_secret" "db_name" {
  secret_id = "db-name"

  labels = {
    label = "db-name"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_name" {
  secret      = google_secret_manager_secret.db_name.id
  secret_data = var.db_name
}

resource "google_secret_manager_secret" "db_user_name" {
  secret_id = "db-user-name"

  labels = {
    label = "db-user-name"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_user_name" {
  secret      = google_secret_manager_secret.db_user_name.id
  secret_data = google_sql_user.my_sql_user.name
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "db-password"

  labels = {
    label = "db-password"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = google_sql_user.my_sql_user.password
}

resource "google_secret_manager_secret" "db_host" {
  secret_id = "db-host"

  labels = {
    label = "db-host"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_host" {
  secret      = google_secret_manager_secret.db_host.id
  secret_data = google_sql_database_instance.mysql_instance.private_ip_address
}

resource "google_secret_manager_secret" "webapp_service_account" {
  secret_id = "webapp-service-account"

  labels = {
    label = "webapp-service-account"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "webapp_service_account" {
  secret      = google_secret_manager_secret.webapp_service_account.id
  secret_data = google_service_account.webapp-service-account.email
}

resource "google_secret_manager_secret" "vm_instance_key" {
  secret_id = "vm-instance-key"

  labels = {
    label = "vm-instance-key"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "vm_instance_key" {
  secret      = google_secret_manager_secret.vm_instance_key.id
  secret_data = google_kms_crypto_key.vm_crypto_key.id
}

resource "google_secret_manager_secret" "subnet" {
  secret_id = "subnet"

  labels = {
    label = "subnet"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "subnet" {
  secret      = google_secret_manager_secret.subnet.id
  secret_data = google_compute_subnetwork.subnetworks["webapp-1"].name
}

resource "google_secret_manager_secret" "domain" {
  secret_id = "domain"

  labels = {
    label = "domain"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "domain" {
  secret      = google_secret_manager_secret.domain.id
  secret_data = var.webapp_env_domain
}

resource "google_secret_manager_secret" "region" {
  secret_id = "region"

  labels = {
    label = "region"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "region" {
  secret      = google_secret_manager_secret.region.id
  secret_data = var.region
}

resource "google_secret_manager_secret" "instance_group_name" {
  secret_id = "instance-group-name"

  labels = {
    label = "instance-group-name"
  }

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "instance_group_nameion" {
  secret      = google_secret_manager_secret.instance_group_name.id
  secret_data = google_compute_region_instance_group_manager.webapp_instance_group.name
}