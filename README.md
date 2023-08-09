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
## External
- python 3
- systemd (exists by default on supported systems)
- corresponding package manager (apt, dpkg, pacman)
- nmap
## Python Libraries
- python-nmap
- psutil
- systemd-python
- distro

# Steps to execute
The first step is to make sure to install the aforementioned dependencies.
<br>
The second step is to define your rules, sevaral of the rule files provide commented out examples, the rules syntax is explained in comments along the examples provided and also in the docs.
<br>
The third step is to execute the tool either:
<br>
`python main.py` for interactive mode or
<br>
`python main.py -h` for help with unattended mode