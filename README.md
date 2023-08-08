```
WIP: Work in progress
```
# General Description
Systell is a tool and library usable to obtain information about linux systems. It can operate in different modes, like for example *local* and *remote*. The different modes are explained further in the docs.

# Supported operative systems
- Linux

## Supported distributions
- Ubuntu
- Archlinux

# Requirements
- python 3
- systemd (exists by default on supported systems)
- corresponding package manager (apt, dpkg, pacman)
- nmap
## Libraries
- python-nmap
- psutil
- systemd-python
- distro
- dateutil

# Steps to execute
`python main.py` for interactive mode or
<br>
`python main.py -h` for help with unattended mode