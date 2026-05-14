group "default" {
  targets = ["iptv-sniffer-web"]
}

target "iptv-sniffer-web" {
  context = "."
  dockerfile = "Dockerfile"
  tags = ["iptv-sniffer-web:v0.8.5"]
  platforms = ["linux/amd64", "linux/arm64"]
}
