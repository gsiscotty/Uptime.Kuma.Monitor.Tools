# EasySystems GmbH Synology Community Package (Basic SPK Skeleton)

This folder contains a **basic community package skeleton** for `synology-monitor` branded for EasySystems GmbH.

It is intentionally minimal, so you can adapt it to your DSM version and signing pipeline.

## Included

- `package/INFO` - package metadata
- `package/scripts/*` - install/uninstall/start/stop hooks
- `package/conf/*` - simple privilege/resource declarations
- `build-spk.sh` - basic local build helper

## Build (basic)

```bash
cd addons/synology-monitor/community-package
chmod +x build-spk.sh
./build-spk.sh
```

Output:
- `dist/synology-monitor-basic.spk`
- `repo/packages.json` (Package Center source index)

## Install (GitHub Package Source)

Use this if you do not want manual `.spk` upload each time.

1. Publish `synology-monitor-basic.spk` as a GitHub release asset in your repository.
2. Commit/push `addons/synology-monitor/community-package/repo/packages.json`.
3. In DSM: Package Center -> Settings -> Package Sources -> Add
4. Use this URL pattern as source:

```text
https://raw.githubusercontent.com/<owner>/<repo>/main/addons/synology-monitor/community-package/repo/packages.json
```

5. Open your source in Package Center and install/update from there.

The package source JSON points to:

```text
https://github.com/<owner>/<repo>/releases/latest/download/synology-monitor-basic.spk
```

Set repository owner/name during build with:

```bash
GITHUB_REPO=<owner>/<repo> ./build-spk.sh
```

## Install (Manual Upload)

1. DSM > Package Center > Manual Install
2. Select `synology-monitor-basic.spk`
3. UI is auto-started by the package scripts (no SSH required)

Then open:
- `http://<nas-ip>:8787`

If needed, control it from Package Center (Start/Stop) for this package.

### SMART helper

During installation, a root helper script is installed:

- `/var/packages/synology-monitor/target/smart-helper.sh`
- writes cache consumed by the package UI/check logic

Then in DSM UI create a root scheduled task that runs this script (for example every 5 minutes), run the task once, and then press "Check elevated access now" in the package UI.
The setup UI includes an "elevated access" status panel to confirm whether helper cache is active.
It also includes an "Auto-create task (beta)" button and status block (best-effort; manual UI setup remains fallback).
The setup UI includes embedded Task Scheduler screenshots to guide users through each step.

## Notes

- This package is a community baseline (no signing, no DSM wizard pages).
- For production distribution, add architecture-specific packaging and signatures.
- DSM 7.3 privilege policy requires package services to run as `package` user (not root).
- EasySystems GmbH: https://www.easysystems.ch/de
- Copyright: Copyright (c) 2026 EasySystems GmbH. All rights reserved.
