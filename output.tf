output "image_logs" {
  value = {
    name = data.google_compute_image.latest_image.name
  }
}

output "webapp-service-account-email" {
  value = {
    name = google_service_account.webapp-service-account.email
  }
}


output "google_storage_project_service_account" {
  value = {
    name = data.google_storage_project_service_account.gcs_account.email_address
  }
}
