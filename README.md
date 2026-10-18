# pySniff

pySniff (`sniffTest.py`) is a passive Wi-Fi sniffer that doubles as a **benchmark against which Wavehound captures are tested**. Because it is a standalone Python/scapy implementation, it provides an independent, second opinion on what is actually on the air: run both tools side by side on the same RF environment and compare what each sees.

## What it does

- Passively captures 802.11 frames on a monitor-mode interface, hopping channels 1, 6, and 11 every 5 seconds (configurable via `IFACE`, `CHANNELS`, `HOP_INTERVAL` at the top of the file).
- Analyzes **Data frames only** (beacons are captured silently in the background so saved handshakes include the SSID, but are not analyzed or printed).
- Prints a console summary of each interesting flow: source/destination MACs with vendor (OUI) lookups, IP addresses where available, frame direction (STA→AP, AP→STA, etc.), 802.11 type/subtype, and the channel it was seen on.

## Protocol parsing

- **DHCPv4** (ports 67/68): message type, hostnames, vendor class, domain name, FQDN (option 81), DNS servers, and any printable strings found in options.
- **DHCPv6** (ports 546/547): message type, transaction ID, DUID decoding (DUID-LLT, DUID-LL, DUID-UUID) with vendor annotations, and vendor strings.
- **mDNS/LLMNR** (ports 5353/5355): questions and answer records, TXT record fields (with base64 blobs summarized rather than dumped), reverse-IPv6 (`ip6.arpa`) conversion back to compressed addresses.
- **SSDP** (port 1900): M-SEARCH / NOTIFY / response classification plus key headers (`ST`, `NT`, `SERVER`, `LOCATION`, `USN`, ...).
- **NetBIOS** (ports 137/138): name decoding from the A-P encoding with human-readable suffix interpretation, plus resolved IPs and datagram/workgroup broadcast intel.
- **DNS** (port 53): queries and answers.
- **SNMP** (ports 161/162): version and community string, flagging the default `public` community as a vulnerability.
- **Dropbox LAN sync** (port 17500): display name and namespace info.
- **Generic JSON catch-all**: any UDP payload containing a JSON object (e.g. TP-Link/Omada discovery on 29810) is summarized by its common keys.
- **Fingerprints without full parses**: STUN, Teredo, PCP, NAT-PMP tagged as protocol observations.
- **ARP replies**: IP↔MAC mapping confirmations.
- **TCP**: SYN/RST/PSH/ACK classification with printable-text extraction from payloads.
- **ICMPv6 Neighbor Solicitation**: who-has queries (router-side noise filtered from the live view).
- **EAPOL-Key frames**: classifies observed handshake messages and retransmissions. Observed EAPOL-Key packets are saved to `eapol_handshakes.pcap`; a cached beacon or probe response is also saved when available to provide network identification information.
- **TKIP frames**: flagged as insecure WPA/TKIP encryption.
- **Catch-all**: encrypted data frames and any unrecognized payload; unknown payloads with printable content are shown, and unknowns are logged with a hex dump to `juicy_exceptions.log`.

## Noise control

- Per-flow de-duplication keys (including payload hashing for discovery traffic and encrypted TCP) so repeated packets are counted, not re-printed.
- A 30-second print cooldown per flow — the counter keeps updating but the console only shows a flow again if something changes or the cooldown expires.
- "Boring ports" (QUIC/443, STUN/3478, NTP/123, standard DNS/53) are silently dropped unless something else interesting was parsed.

## Privacy and authorization

Use this tool only on wireless networks and devices you own or have explicit permission to monitor. Passive capture can still collect sensitive information, including device identifiers, network metadata, and packet contents.

Packet captures (`.pcap` / `.pcapng`), diagnostic logs, and generated state files may contain sensitive data. Review them carefully before sharing, and do not commit them to the repository.

## Running it

Requires root (raw packet access) and a monitor-mode interface (default `wlan1mon`; create one with `airmon-ng start wlan1` or `iw dev wlan0 set monitor none`).

```
sudo python3 sniffTest.py
```

Ctrl+C stops gracefully at the end of the current channel hop. Dependencies: `scapy`, `netaddr`. Optional: the Wireshark `manuf` database at `/usr/share/wireshark/manuf` for OUI vendor fallback (netaddr's OUI registration is used first).
