#!/bin/bash

iptables -P OUTPUT DROP  # default policy: drop all traffic
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS queries to dnsmasq
iptables -A OUTPUT -d 10.10.10.2 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d 10.10.10.2 -p tcp --dport 53 -j ACCEPT

# Exempt allowed destinations (resolved on the host by `run-sandbox.sh`) from the DNAT redirects below, so they reach the real
# internet instead of INetSim / SSLsplit. Note that there is a race condition here: A domain might change its IP address(es)
# after it was resolved by `run-sandbox.sh` but before it's resolved again in the sandbox container, in which case the traffic
# would be redirected to INetSim / SSLsplit.
while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    iptables -t nat -A OUTPUT -p tcp -d "$ip" --dport 80  -j RETURN
    iptables -t nat -A OUTPUT -p tcp -d "$ip" --dport 443 -j RETURN
    iptables        -A OUTPUT -p tcp -d "$ip" --dport 80  -j ACCEPT
    iptables        -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
done < /etc/malbox/allowed-ips.txt

# Redirect HTTP traffic directly to INetSim
iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination 10.10.10.3
iptables        -A OUTPUT -p tcp -d 10.10.10.3 --dport 80  -j ACCEPT

# Redirect HTTPS traffic to SSLsplit that terminates TLS and forwards the traffic to INetSim
iptables -t nat -A OUTPUT -p tcp --dport 443  -j DNAT --to-destination 10.10.10.4
iptables        -A OUTPUT -p tcp -d 10.10.10.4 --dport 443 -j ACCEPT
