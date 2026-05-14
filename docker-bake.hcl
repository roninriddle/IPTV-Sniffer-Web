group "default" {
  targets = ["iptv-sniffer-web"]
}

target "iptv-sniffer-web" {
  context = "."
  dockerfile = "Dockerfile"
  tags = ["iptv-sniffer-web:0.6.8"]
  platforms = ["linux/amd64", "linux/arm64"]
}
