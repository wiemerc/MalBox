#!/bin/bash

printf "Running Falco on the captured system calls...\n"
rm -f logs/falco-alerts.json
falco -o engine.kind=replay \
    -o engine.replay.capture_file=traces/sandbox-all-syscalls.scap \
    -o json_output=true \
    -o file_output.enabled=true \
    -o file_output.filename=logs/falco-alerts.json \
    -o stdout_output.enabled=false \
    -o log_level=warning \
    -o libs_logger.enabled=false
printf "\nFalco alerts:\n"
if [[ -f logs/falco-alerts.json ]]; then
    jq -r '
        (if .priority == "Emergency" or .priority == "Alert" or .priority == "Critical" or .priority == "Error" then "\u001b[1;31m"
        elif .priority == "Warning" or .priority == "Notice" then "\u001b[1;33m"
        else "\u001b[1;36m" end) as $color |
        "\($color)[\(.priority)]\u001b[0m \(.output)"
    ' logs/falco-alerts.json
fi

printf "\n"
rm -f logs/suricata/*
# TODO: Can we run Suricata as regular user?
printf "Running Suricata on the captured network traffic...\n"
sudo suricata \
    --set vars.address-groups.HOME_NET="[10.10.10.5/32]" \
    --set pcap-file.checksum-checks=no \
    -l logs/suricata \
    -r traces/sandbox-complete-traffic.pcap
printf "Running Suricata on the decrypted TLS traffic...\n"
sudo suricata \
    --set vars.address-groups.HOME_NET="[10.10.10.5/32]" \
    --set pcap-file.checksum-checks=no \
    -l logs/suricata \
    -r traces/sandbox-decrypted-tls-traffic.pcap
printf "\nSuricata alerts:\n"
jq -r '
    select(.event_type == "alert") |
    (.alert.severity // 3) as $sev |
    (if $sev == 1 then "\u001b[1;31m" elif $sev == 2 then "\u001b[1;33m" else "\u001b[1;36m" end) as $color |
    "\($color)[\(.app_proto)]\u001b[0m \(.alert.signature)"
' logs/suricata/eve.json

# TODO: The current sysdig version (0.41.3) doesn't decode the path argument of statx() calls, so files / folders might be missed.
printf "\nList of touched files / folders (except in /{dev,lib,sys,usr}):\n"
{
    sysdig -r traces/sandbox-all-syscalls.scap 'evt.category=file and fd.name exists' -p '%fd.name'
    sysdig -r traces/sandbox-all-syscalls.scap 'evt.type=newfstatat' -p '%evt.arg.path'
} | sort -u | grep -vP '^/(dev|lib|sys|usr)' | grep -v UNKNOWN

printf "\nList of queried DNS domains:\n"
jq -r 'select(.event_type == "dns" and .dns.type == "query") | "\(.dns.rrtype) \(.dns.rrname)"' < logs/suricata/eve.json

printf "\n List of TLS SNIs:\n"
jq -r 'select(.event_type == "tls") | .tls.sni' < logs/suricata/eve.json

printf "\n List of HTTP(S) requests:\n"
jq -r '
    select(.event_type == "http") |
    "\(.http.http_method) \(.http.hostname) \(.http.url) \(.http.status) \(.http.http_content_type)"
' < logs/suricata/eve.json

# TODO: Exit with status 1 if alerts were found
