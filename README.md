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
