group "default" {
  targets = ["iptv-sniffer-web"]
}

target "iptv-sniffer-web" {
  context = "."
  dockerfile = "Dockerfile"
  tags = ["roninriddle/iptv-sniffer-web:1.3.5-test"]
  platforms = ["linux/amd64", "linux/arm64"]
}
