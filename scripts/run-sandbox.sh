#!/bin/bash

set -o errexit
set -o pipefail

export PODMAN_COMPOSE_WARNING_LOGS=0

printf "Setting up folders...\n"
rm -rf traces/
mkdir traces/
# Making traces/ world-writable is necessary for the SSLsplit container to be able to write into this folder because that container's
# sslsplit user with UID 1000 gets mapped to a completely different UID on the host (behavior of rootless Podman).
chmod 0777 traces/
rm -rf logs
mkdir -p logs/suricata

printf "Generating dnsmasq config for allowed domains...\n"
: > run/dnsmasq-allowed-domains.conf
while IFS= read -r domain; do
    if [[ $domain == '#'* ]]; then
        continue
    fi
    echo "server=/$domain/10.10.10.1" >> run/dnsmasq-allowed-domains.conf
done < conf/allowed-domains.txt

printf "Resolving allowed domains to IP addresses for sandbox-init's iptables rules...\n"
: > run/allowed-ips-v4.txt
: > run/allowed-ips-v6.txt
while IFS= read -r domain; do
    if [[ $domain == '#'* ]]; then
        continue
    fi
    getent ahostsv4 "$domain" | awk '{print $1}' | sort -u >> run/allowed-ips-v4.txt || true
    getent ahostsv6 "$domain" | grep -v '^::ffff' | awk '{print $1}' | sort -u >> run/allowed-ips-v6.txt || true
done < conf/allowed-domains.txt

printf "Starting containers...\n"
podman compose up -d

printf "Starting tshark...\n"
# With `nsenter` the `tshark` command doesn't show up in the container's process list, so the malware can't see it. However, we
# have to let `tshark` write its output to stdout (`-w -`) and redirect stdout to a file because of a weird combination of
# permissions and `dumpcap` (which is run by `tshark`) behavior. On the EC2 instance `/home/malbox` is 0700, so even though
# `traces/` is 0777, nobody except malbox can walk through the home directory to reach it. And the fact that `tshark` is run as
# root (because `nsenter` is run as root) doesn't help here either because `dumpcap` drops all privileges except CAP_NET_RAW and
# CAP_NET_ADMIN *before* it tries to open the output file.
sudo nsenter -t $(podman inspect -f '{{.State.Pid}}' sandbox) -n \
    tshark -i eth0 -n -s0 -w - > traces/sandbox-complete-traffic.pcap 2> /dev/null &
tshark_pid=$!
# `sysdig` expects the *short* container id (the first 12 digits).
printf "Starting sysdig...\n"
sudo sysdig --modern-bpf -w traces/sandbox-all-syscalls.scap container.id=$(podman inspect -f '{{.Id}}' sandbox | head -c12) &
sysdig_pid=$!

read -p "Press any key to see the container logs, press Ctrl-C to stop the sandbox... "
podman compose logs --follow --names || true
printf "Stopping sysdig and tshark...\n"
kill $sysdig_pid $tshark_pid
printf "Stopping containers...\n"
podman compose down

printf "Fixing permissions of traces/...\n"
chmod 0755 traces/
sudo chown $USER:$USER traces/*
chmod 0644 traces/*
