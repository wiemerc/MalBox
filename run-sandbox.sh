#!/bin/bash

export PODMAN_COMPOSE_WARNING_LOGS=0

printf "Setting up folders...\n"
rm -rf traces/
mkdir traces/
# Making traces/ world-writable is necessary for the SSLsplit container to be able to write into this folder because that container's
# sslsplit user with UID 1000 gets mapped to a completely different UID on the host (behavior of rootless Podman).
chmod 0777 traces/
rm -rf logs
mkdir -p logs/suricata

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

printf "Fixing permissions of traces/...\n"
chmod 0755 traces/
sudo chown $USER:$USER traces/*
chmod 0644 traces/*
