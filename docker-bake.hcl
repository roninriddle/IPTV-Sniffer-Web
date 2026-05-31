group "default" {
  targets = ["iptv-sniffer-web"]
}

target "iptv-sniffer-web" {
  context = "."
  dockerfile = "Dockerfile"
  tags = ["iptv-sniffer-web:v0.9.93"]
  platforms = ["linux/amd64", "linux/arm64"]
}
