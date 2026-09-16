#!/bin/bash

export PODMAN_COMPOSE_WARNING_LOGS=0

rm -f traces/*
printf "Starting containers...\n"
podman compose up -d
# With `nsenter` the `tshark` command doesn't show up in the container's process list, so the malware can't see it.
printf "Starting tshark...\n"
sudo nsenter -t $(podman inspect -f '{{.State.Pid}}' sandbox) -n \
    tshark -i eth0 -n -s0 -w traces/sandbox-complete-traffic.pcap > /dev/null 2>&1 &
tshark_pid=$!
# `sysdig` expects the *short* container id (the first 12 digits).
printf "Starting sysdig...\n"
sudo sysdig --modern-bpf -w traces/sandbox-all-syscalls.scap container.id=$(podman inspect -f '{{.Id}}' sandbox | head -c12) &
sysdig_pid=$!

read -p "Press any key to see the container logs, press Ctrl-C to stop the sandbox... "
podman compose logs --follow --names
printf "Stopping sysdig and tshark...\n"
kill $sysdig_pid $tshark_pid
printf "Stopping containers...\n"
podman compose down
