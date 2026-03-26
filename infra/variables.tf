variable "flavor" {
  description = "OVH Public Cloud instance flavor (e.g., d2-4, b3-8)"
  type        = string
  default     = "d2-4"
}

variable "ssh_key_name" {
  description = "Name for the generated SSH keypair in OpenStack"
  type        = string
  default     = "proxy-scanner"
}
