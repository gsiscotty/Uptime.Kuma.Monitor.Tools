# Release Checklist - EasySystems GmbH - Kuma Monitor Addon

Use this checklist for every release. Do not skip steps.

## 1) Version and metadata

- [ ] `package/INFO` version is bumped (new unique version).
- [ ] `package/INFO` name/description/URLs are correct.
- [ ] `repo/packages.json` is regenerated and matches `package/INFO`.

## 2) Build and package integrity

- [ ] Build with repo target:
  - `GITHUB_REPO=<owner>/<repo> ./build-spk.sh`
- [ ] Build output exists:
  - `dist/synology-monitor-basic.spk`
  - `repo/packages.json`
- [ ] `repo/packages.json` fields are correct:
  - `version` matches `INFO`
  - `link` points to the intended GitHub release URL
  - `checksum_sha256` exists
  - `size` is non-zero

## 3) Repository hygiene (unwanted cleanup)

- [ ] `.build/` is NOT tracked in git.
- [ ] `dist/` is NOT tracked in git.
- [ ] No temporary artifacts are committed (tarballs, local logs, caches).
- [ ] No secrets/credentials are committed.

## 4) GitHub release readiness

- [ ] Commit includes only intended source/config/docs changes.
- [ ] Create tag for this version.
- [ ] Create GitHub Release for the tag.
- [ ] Upload release asset with exact filename:
  - `synology-monitor-basic.spk`

## 5) Package source validation

- [ ] Raw package source URL loads in browser:
  - `https://raw.githubusercontent.com/<owner>/<repo>/main/addons/synology-monitor/community-package/repo/packages.json`
- [ ] Release asset URL returns the file (not 404):
  - `https://github.com/<owner>/<repo>/releases/latest/download/synology-monitor-basic.spk`

## 6) DSM verification

- [ ] Refresh Package Center source.
- [ ] Package is visible in source list.
- [ ] Install/upgrade succeeds.
- [ ] UI opens on configured port.
- [ ] Run one monitor check and confirm push result in Uptime Kuma.

