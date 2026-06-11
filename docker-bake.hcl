group "default" {
  targets = ["iptv-sniffer-web"]
}

target "iptv-sniffer-web" {
  context = "."
  dockerfile = "Dockerfile"
  tags = ["roninriddle/iptv-sniffer-web:v1.0.0", "roninriddle/iptv-sniffer-web:latest"]
  platforms = ["linux/amd64", "linux/arm64"]
}
