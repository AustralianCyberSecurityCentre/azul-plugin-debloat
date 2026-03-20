# Azul Plugin Debloat

Debloat removes excess garbage from bloated executables.

## Installation

```bash
pip install azul-plugin-debloat
```

## Usage

Usage on local files:

```bash
$ azul-plugin-debloat malware.file
----- AzulPluginDebloat results -----
COMPLETED

events (2)

event for binary:80c8984124c10649e5d4f64d1204d6375ee8a95203e0c91da3763d80381e1f93:None
  {}
  output features:
    bloat_removed: 46.7KiB
     bloat_tactic: Bloat in PE resources

event for binary:8f341ecc017430a13367234aeff62bba9e71a252a15be8a6e93eb53bce20a581:None
  {'action': 'de-bloated'}
  child of binary:80c8984124c10649e5d4f64d1204d6375ee8a95203e0c91da3763d80381e1f93
  output data streams (1):
    226622 bytes - EventData(hash='8f341ecc017430a13367234aeff62bba9e71a252a15be8a6e93eb53bce20a581', label='content')

Feature key:
  bloat_removed:  Total bloated bytes removed from the binary in a human readable format.
  bloat_tactic:  Bloat tactic found in the binary.
```

Check `azul-plugin-debloat --help` for advanced usage.

## Dependency management

Dependencies are managed in the pyproject.toml and debian.txt file.

Version pinning is achieved using the `uv.lock` file.
Because the `uv.lock` file is configured to use a private UV registry, external developers using UV will need to delete the existing `uv.lock` file and update the project configuration to point to the publicly available PyPI registry instead.

To add new dependencies it's recommended to use uv with the command `uv add <new-package>`
    or for a dev package `uv add --dev <new-dev-package>`

The tool used for linting and managing styling is `ruff` and it is configured via `pyproject.toml`

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
