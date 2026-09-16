SHELL := /bin/bash

.PHONY: install cert containers run analyze

install:
# TODO: Should we create a VM image with all the necessary tools?
	sudo dnf install openssl podman podman-compose suricata wireshark-cli
	sudo suricata-update
	sudo rpm --import https://download.sysdig.com/DRAIOS-GPG-KEY.public
	sudo curl -o /etc/yum.repos.d/draios.repo https://download.sysdig.com/stable/rpm/draios.repo
	sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
	sudo curl -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
	sudo yum install -y sysdig falco
	sudo systemctl disable falco  # We don't need the service, just the tool.

cert:
	openssl genrsa -out sslsplit-ca.key 4096
	openssl req -new -x509 -sha256 -days 365 -key sslsplit-ca.key -out sslsplit-ca.crt -subj "/CN=ABS CloudOps Sandbox CA/OU=ABS CloudOps/O=Allianz Technology/C=DE"

containers:
# TODO: Can we build the images with podman compose?
	podman build -t inetsim -f Dockerfile-inetsim .
	podman build -t sslsplit -f Dockerfile-sslsplit .
	podman build -t sandbox -f Dockerfile-sandbox .

run:
	./run-sandbox.sh

analyze:
	falco -o engine.kind=replay -o engine.replay.capture_file=traces/sandbox-all-syscalls.scap
# TODO: Can we run Suricata as regular user?
	rm -f logs/suricata/*
	sudo suricata -v \
		--set vars.address-groups.HOME_NET="[10.10.10.5/32]" \
		--set pcap-file.checksum-checks=no \
		-l logs/suricata \
		-r traces/sandbox-complete-traffic.pcap
	sudo suricata -v \
		--set vars.address-groups.HOME_NET="[10.10.10.5/32]" \
		--set pcap-file.checksum-checks=no \
		-l logs/suricata \
		-r traces/sandbox-decrypted-tls-traffic.pcap
	cat logs/suricata/fast.log
