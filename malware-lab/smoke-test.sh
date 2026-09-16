#!/bin/bash

# Falco
# The command below triggers the rule "Read sensitive file untrusted". A normal `cat` doesn't do it because the rule only fires
# if the `open` syscall was successful, which the `O_PATH` flag ensures (only read / execute permission on `/etc` necessary, not
# on the file as the file itself is not opened, see `open(2)` for more details).
python3 -c 'import os; os.open("/etc/shadow", os.O_PATH)'

# Suricata
dig +noall +answer suricata.onion  # triggers rule 2014939 (ET INFO DNS Query for TOR Hidden Domain)
curl -v -A 'PHP/' https://www.heise.de  # triggers rule 2013058 (ET WEB_SERVER Outbound PHP User-Agent)
# TODO: The command can only trigger a rule if we allow eicar.com *and* decrypt the traffic -> separate SSLsplit instance
# curl -v -o /dev/null https://secure.eicar.org/eicar.com  # triggers TODO
