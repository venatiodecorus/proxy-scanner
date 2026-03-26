output "instance_ip" {
  description = "Public IPv4 address of the proxy-scanner VPS"
  value       = openstack_compute_instance_v2.proxy_scanner.access_ip_v4
}

output "ssh_private_key" {
  description = "SSH private key for accessing the VPS (add to GitHub Actions secrets as VPS_SSH_KEY)"
  value       = openstack_compute_keypair_v2.proxy_scanner.private_key
  sensitive   = true
}

output "ssh_command" {
  description = "SSH command to connect to the VPS"
  value       = "ssh -i proxy-scanner.pem ubuntu@${openstack_compute_instance_v2.proxy_scanner.access_ip_v4}"
}

output "tunnel_command" {
  description = "SSH tunnel command to access the API locally"
  value       = "ssh -i proxy-scanner.pem -L 8080:127.0.0.1:8080 ubuntu@${openstack_compute_instance_v2.proxy_scanner.access_ip_v4}"
}
