<!--cSpell:dictionaries: de-de -->

## 28.08.2026
Mit den Schlüsseln / Secrets, die mitmproxy bzw. curl in SSLKEYLOGFILE schreiben, kann Wireshark momentan den Verkehr nicht entschlüsseln -> vielleicht doch PolarProxy und INetSim verwenden?


## 01.09.2026
Es lag nicht an den Sitzungsschlüsseln sondern an den iptables-Regeln, siehe Kommentar in `start-proxy.sh`. Aber trotzdem habe ich mich für ein anderes Setup entschieden, und zwar:
- dnsmasq für DNS - weil dnsmasq im Gegensatz zu INetSim für bestimmte Domänen die echte IP-Adresse zurückgeben kann -> wichtig wenn ich bestimmte Domänen, wie z. B. pypi.org, erlauben will. Ausserdem kann INetSim aus irgendwelchen Gründen im Container nicht auf Port 53 hören.
- INetSim als Web Server - scheint der "Industriestandard" zu sein. Ausserdem muss ich dann nicht die Funktionalität in mitmproxy nachbauen, den ich sowieso nicht verwenden will -> siehe nächster Punkt.
- PolarProxy oder SSLsplit als transparenter Proxy - beide können den entschlüsselten Verkehr als PCAP-Datei abspeichern. Wireshark / tshark kann das nur in einem Format, das Suricata nicht versteht (nur der TLS-Verkehr, ohne Ethernet / IP / TCP).
- Suricata oder Snort zur Erkennung von auffälligem Verhalten


## 03.09.2026
Als Alternative zu Containern vielleicht MicroVMs verwenden?


## 07.09.2026
Warum SSLsplit und nicht PolarProxy?
- Open Source
- einfacher zu installieren (Pakete für Debian und Fedora)
- Man kann SSLsplit ein selber erzeugtes Root-CA-Zert übergeben (wie auch mitmproxy). PolarProxy erzeugt selber ein Zert, das man exportieren kann.


## 16.09.2026
Im Artikel auch beschreiben, wie die jetzige Architektur entstanden ist: Warum welche Tools, Ideen / Ansätze, die nicht funktioniert haben...


## 05.10.2026
Mit LiteLLM (in der dedizierten VM) getestet (gute Beschreibung des Angriffs auf LiteLLM: https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/):
- infizierte Version von MalwareBazaar heruntergeladen, entpackt und im Sandbox-Container ausgeführt
- keine Falco-Alarme (bei `/etc/shadow` gibt es das gleiche Problem wie in `smoke-test.sh` beschrieben)
- folgende Suricata-Alarme:
    ```
    [dns] ET MALWARE Observed DNS Query to TeamPCP litellm Supply Chain Attack Domain (litellm .cloud)
    [http] ET HUNTING curl User-Agent to Dotted Quad
    [tls] ET MALWARE Observed TeamPCP litellm Supply Chain Attack Domain (litellm .cloud in TLS SNI)
    [http] ET MALWARE TeamPCP CnC Activity Observed
    [http] ET MALWARE LiteLLM & Telnyx Supply Chain (TeamPCP) Exfiltration
    ```
- Mit den .scap- und .pcap-Dateien kann man das im Artikel beschriebene Verhalten gut nachvollziehen (Sammeln der Informationen, Suchen nach Geheimnissen, Verschlüsseln und Hochladen der Daten).
- Hochgeladene Daten und der Schlüssel, mit dem sie verschlüsselt wurden, lassen sich mit Wireshark und Stratoshark extrahieren => Daten im Klartext
