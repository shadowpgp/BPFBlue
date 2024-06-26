#!/bin/bash

# eBPF passive security monitoring tool
# Copyright (C) 2023  Shadowpgp
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

if [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ "$#" -eq 0 ]; then
    echo """
    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄   ▄▄ ▄▄▄▄▄▄▄ 
    █  ▄    █       █       █  ▄    █   █   █  █ █  █       █
    █ █▄█   █    ▄  █    ▄▄▄█ █▄█   █   █   █  █ █  █    ▄▄▄█
    █       █   █▄█ █   █▄▄▄█       █   █   █  █▄█  █   █▄▄▄ 
    █  ▄   ██    ▄▄▄█    ▄▄▄█  ▄   ██   █▄▄▄█       █    ▄▄▄█
    █ █▄█   █   █   █   █   █ █▄█   █       █       █   █▄▄▄ 
    █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄█   █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█ V1.1

    Created by @shadowpgp aka fcn
    """
    echo "BPF passive security monitoring script"
    echo "Usage: $0 [probe]"
    echo ""
    echo "Available probes:"
    echo "  execve   trace syscall execve (execution of a program)"
    echo "  network  trace network enter and exit events"
    echo "  sniff    sniff network traffic (Warning: this is a heavy process)"
    echo "  open     trace syscall open (opening of a file)"
    echo "  clone    trace syscall clone (creation of a new process)"
    echo "  socket   trace syscall socket (creation of a network socket)"
    echo "  bind     trace syscall bind (binding of a network socket to a local address)"
    echo "  listen   trace syscall listen (listening for incoming connections on a network socket)"
    echo "  connect  trace syscall connect (connecting to a remote address)"
    echo "  event   trace kernel events (listen to the kernel ring 0)"
    echo ""
    echo "This script uses eBPF and bpftrace to passively monitor the behavior of system calls on a Linux system."
    echo "The script can be used to gain insights into system activity, detect malicious activity, or monitor system performance."
    echo ""
    echo "Example: $0 execve"
    exit 0
fi

# Syscall execve
execve_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf(\" Execve syscall traced : Command - %s, Filename - %s, PID - %d\\n\", comm, str(args->filename), pid); }'"

# Network analysis
network_analysis="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_socket { printf(\"Entering Sock : Program name - %s, PID - %d\\n\", comm, pid); } tracepoint:syscalls:sys_exit_socket { printf(\"Exiting Sock : Program name - %s, PID - %d\\n\", comm, pid); }'"

# Network sniffing
network_sniffing="sudo tcpdump -vvv -i any"

# Syscall open
open_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf(\" Open syscall traced : Filename - %s, PID - %d\\n\", str(args->filename), pid); }'"

# Syscall clone
clone_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_clone { printf(\" Clone syscall traced : Command - %s, PID - %d\\n\", comm, pid); }'"

# Syscall socket
socket_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_socket { printf(\" Socket syscall traced : Domain - %d, PID - %d\\n\", args->domain, pid); }'"

# Syscall bind
bind_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_bind { printf(\" Bind syscall traced : Socket - %s, PID - %d\\n\", comm, pid); }'"

# Syscall listen
listen_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_listen { printf(\" Listen syscall traced : Socket - %s, PID - %d\\n\", comm, pid); }'"

# Syscall connect
connect_command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf(\" Connect syscall traced : Socket - %s, PID - %d\\n\", comm, pid); }'"

# Clone syscall
clone_process="sudo bpftrace -e 'kprobe:sys_clone { printf(\"Clone syscall traced : Flags - %x, PID - %d\\n\", arg1, pid); }'"

# Event trace
event_command="sudo bpftrace -e 'tracepoint:sched:sched_switch { printf(\"Event : %s %s\\n\", args->prev_comm, args->next_comm); }'"

probe="$1"

case "$probe" in
    "execve")
        command=$execve_command
        ;;
    "network")
        command=$network_analysis
        ;;
    "sniff")
        command=$network_sniffing
        ;;
    "open")
        command=$open_command
        ;;
    "clone")
        command=$clone_command
        ;;
    "socket")
        command=$socket_command
        ;;
    "bind")
        command=$bind_command
        ;;
    "listen")
        command=$listen_command
        ;;
    "connect")
        command=$connect_command
        ;;
    "clone")
        command=$clone_process
        ;;
    "event")
        command=$event_command
        ;;
    *)
        echo "Invalid probe. Use -h or --help to see the available probes."
        exit 1
        ;;
esac

echo """
    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄   ▄▄ ▄▄▄▄▄▄▄ 
    █  ▄    █       █       █  ▄    █   █   █  █ █  █       █
    █ █▄█   █    ▄  █    ▄▄▄█ █▄█   █   █   █  █ █  █    ▄▄▄█
    █       █   █▄█ █   █▄▄▄█       █   █   █  █▄█  █   █▄▄▄ 
    █  ▄   ██    ▄▄▄█    ▄▄▄█  ▄   ██   █▄▄▄█       █    ▄▄▄█
    █ █▄█   █   █   █   █   █ █▄█   █       █       █   █▄▄▄ 
    █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄█   █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█ V1.1

    Created by @shadowpgp aka fcn
"""
echo "BPF passive security monitoring script"
echo "Executing probe: $probe"
echo "Running command: $command"
eval "$command"

