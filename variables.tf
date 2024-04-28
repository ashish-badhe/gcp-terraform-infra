variable "project" {}

variable "region" {
  default = "us-east1"
}

variable "zone" {
  default = "us-east1-b"
}

variable "routing_mode" {}

variable "image_family" {}

variable "machine_type" {}

variable "database_version" {}

variable "availability_type" {}

variable "ipv4_enabled" {}

variable "deletion_protection" {}

variable "db_name" {}

variable "sql_username" {}

variable "private_ip_name" {}

variable "private_ip_addressType" {}

variable "private_ip_purpose" {}

variable "port" {}

variable "environment" {}

variable "zone_name" {}

variable "admin_role" {}

variable "metricWriter_role" {}

variable "webapp_service_account_id" {}

variable "service_account_display_name" {}

variable "token_creator_role" {}

variable "vpc_connector_name" {}

variable "vpc_connector_cidr" {}

variable "vpc_connector_machine_type" {}

variable "pubsub_topic_name" {}

variable "pubsub_topic_role" {}

variable "pubsub_subscription_name" {}

variable "pubsub_subscription_role" {}

variable "cloudfunction_bucket_name" {}

variable "cloudfunction_bucket_object_name" {}

variable "cloudfunction_name" {}

variable "cloudfunction_env_api_key" {}

variable "webapp_env_domain" {}

variable "cloudfunction_env_domain" {}

variable "cloudfunction_event_type" {}

variable "cloudfunction_invoker_role" {}

variable "cloudfunction_run_invoker_role" {}

variable "vpc_names" {
  description = "VPC Names"
  type = map(object({
    name                            = string,
    auto_create_subnetworks         = bool
    routing_mode                    = string
    delete_default_routes_on_create = bool
  }))
}

variable "subnet_list" {
  description = "Subnet Name"
  type = map(object({
    name                     = string,
    ip_cidr_range            = string,
    network                  = string,
    private_ip_google_access = bool
  }))
}
