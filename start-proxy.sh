#!/bin/bash

# TODO: SSLsplit doesn't create a matching cert for an IP address as host, e. g. https://1.2.3.4/. The cert doesn't contain a SAN
# for the IP address in this case.
#
# Why: SSLsplit generates each leaf cert's SAN from whatever it considers the connection's "target". Here that's the static
# target address configured below (10.10.10.3, INetSim) -- not the real IP the malware dialed -- because we deliberately always
# forward decrypted traffic to INetSim regardless of the actual destination. Switching to SSLsplit's NAT-based original-
# destination recovery (`-e netfilter` / `-e tproxy`, see `sslsplit -E`) wouldn't help either: the DNAT rewrite happens in
# `sandbox`'s network namespace (via `sandbox-init`), and the conntrack state that `SO_ORIGINAL_DST` reads doesn't cross network
# namespace boundaries -- by the time the connection reaches this container, the pre-redirect destination is already gone.
#
# A real fix would mean moving the interception into this container's own netns instead: policy-route (not DNAT) sandbox's
# port 443 traffic through sslsplit as a next-hop, use `iptables -j TPROXY` + local routing here to intercept it transparently
# (where SO_ORIGINAL_DST would work), run sslsplit with `-e tproxy`, and add a *separate* redirect for sslsplit's own outbound
# connection attempts back to INetSim (otherwise sslsplit would try to reach the real destination it just recovered). That's
# roughly the same complexity as the egress-gateway design documented in docker-compose.yml, which we decided against for
# similar reasons.
#
# Left as a known limitation: this only matters for malware that both connects via a raw IP literal over HTTPS (SNI is defined
# to exclude IP literals, so there's nothing else to match against) *and* actually validates the cert's SAN against the IP it
# dialed -- plenty of malware HTTP(S) clients don't bother with strict cert validation at all.
/usr/bin/sslsplit -D \
    -k /home/sslsplit/sslsplit-ca.key \
    -c /home/sslsplit/sslsplit-ca.crt \
    -X /home/sslsplit/traces/sandbox-decrypted-tls-traffic.pcap \
    https 10.10.10.4 443 \
    10.10.10.3 443
