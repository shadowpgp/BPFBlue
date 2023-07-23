# BPFBlue

## eBPF passive security monitoring tool

## requirements

`sudo, bpftrace and tcpdump`

```
sudo apt install sudo bpftrace tcpdump
```

## Install:

Warning ! Program using sudo.

```bash
git clone https://github.com/shadowpgp/BPFBlue.git
cd BPFBlue
sudo cp BPFBlue.sh /usr/bin/bpfblue
sudo chmod +x /usr/bin/bpfblue
bpfblue [probe]
```

## Usage

```txt

    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄   ▄▄ ▄▄▄▄▄▄▄ 
    █  ▄    █       █       █  ▄    █   █   █  █ █  █       █
    █ █▄█   █    ▄  █    ▄▄▄█ █▄█   █   █   █  █ █  █    ▄▄▄█
    █       █   █▄█ █   █▄▄▄█       █   █   █  █▄█  █   █▄▄▄ 
    █  ▄   ██    ▄▄▄█    ▄▄▄█  ▄   ██   █▄▄▄█       █    ▄▄▄█
    █ █▄█   █   █   █   █   █ █▄█   █       █       █   █▄▄▄ 
    █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄█   █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█ V1.1

    Created by @shadowpgp aka fcn
    
BPF passive security monitoring script
Usage: BPFBlue.sh [probe]

Available probes:
  execve   trace syscall execve (execution of a program)
  network  trace network enter and exit events
  sniff    sniff network traffic (Warning: this is a heavy process)
  open     trace syscall open (opening of a file)
  clone    trace syscall clone (creation of a new process)
  socket   trace syscall socket (creation of a network socket)
  bind     trace syscall bind (binding of a network socket to a local address)
  listen   trace syscall listen (listening for incoming connections on a network socket)
  connect  trace syscall connect (connecting to a remote address)

This script uses eBPF and bpftrace to passively monitor the behavior of system calls on a Linux system.
The script can be used to gain insights into system activity, detect malicious activity, or monitor system performance.

Example: BPFBlue.sh execve
```
