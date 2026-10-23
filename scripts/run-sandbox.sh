#!/bin/bash

set -o errexit
set -o pipefail
# TODO: Should we trap SIGTERM and SIGINT?

export PODMAN_COMPOSE_WARNING_LOGS=0

if [[ $# == 0 ]]; then
    mode=interactive
elif [[ $# == 1 ]]; then
    if [[ $(basename "$1") == requirements.txt ]]; then
        mode=python
    elif [[ $(basename "$1") == package.json ]]; then
        mode=npm
    else
        printf "List of packages has to be provided as requirements.txt or package.json\n"
        exit 1
    fi
else
    printf "Usage: run-sandbox.sh [package.json | requirements.txt]\n"
    exit 1
fi

printf "Setting up folders...\n"
rm -rf run/
mkdir run/
rm -rf traces/
mkdir traces/
# Making traces/ world-writable is necessary for the SSLsplit container to be able to write into this folder because that container's
# sslsplit user with UID 1000 gets mapped to a completely different UID on the host (behavior of rootless Podman).
chmod 0777 traces/
rm -rf logs/
mkdir -p logs/suricata/

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
podman compose --podman-run-args=--http-proxy=false up -d

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

case $mode in
    interactive)
        read -p "No list of packages was provided, press any key to see the container logs, perform some action in the sandbox container, then press Ctrl-C to stop the sandbox... "
        podman compose logs --follow --names || true
        ;;
    
    python)
        printf "Installing Python packages listed in $1...\n"
        podman cp $1 sandbox:requirements.txt
        if [[ -f conf/pip.conf ]]; then
            podman cp conf/pip.conf sandbox:pip.conf
            podman exec sandbox env PIP_CONFIG_FILE=./pip.conf pip install -r requirements.txt || true
        else
            podman exec sandbox pip install -r requirements.txt || true
        fi
        # TODO: Should we also import all packages? The problem is that sometimes the packages are named differently in
        # requirements.txt than in the code, e. g. PyYAML -> yaml.
        ;;
    
    npm)
        podman cp $1 sandbox:package.json
        # TODO
        ;;
esac

printf "Stopping sysdig and tshark...\n"
kill $sysdig_pid $tshark_pid
printf "Stopping containers...\n"
podman compose down

printf "Fixing permissions of traces/...\n"
chmod 0755 traces/
sudo chown $USER:$USER traces/*
chmod 0644 traces/*
