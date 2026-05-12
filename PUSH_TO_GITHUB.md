# Push to GitHub

This repository has been initialized on branch `main` with the first release commit:

```text
Release IPTV Sniffer Web v0.5
```

## Push to the target repository

```bash
git remote add origin https://github.com/roninriddle/-IPTV-Sniffer-Web.git
git push -u origin main
```

If `origin` already exists:

```bash
git remote set-url origin https://github.com/roninriddle/-IPTV-Sniffer-Web.git
git push -u origin main
```

## If the GitHub repository has an existing README or other initial commit

Use this only when you intentionally want to preserve and merge the existing remote history:

```bash
git remote add origin https://github.com/roninriddle/-IPTV-Sniffer-Web.git
git fetch origin
git merge origin/main --allow-unrelated-histories
git push -u origin main
```

If the remote repository is intentionally empty, the first push command is sufficient.

## Publish Docker images

The `v*` tag workflow publishes multi-arch images to GHCR and Docker Hub.

Before pushing a release tag, add these GitHub Actions secrets to the target repository:

```text
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
```

Then push the tag:

```bash
git tag v0.5.3
git push origin v0.5.3
```
