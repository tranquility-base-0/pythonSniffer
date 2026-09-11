#!/usr/bin/env python3
# sniffTestv9.py
# Passive Wi-Fi sniffer with richer DHCP, SSDP, and mDNS parsing.
# Channel hops (1,6,11), extracts DHCP (magic cookie), SSDP, mDNS records.
# Prints MAC flow key + direction, vendor, frame type/subtype and channel.

import os, sys, time, threading, subprocess, json, re, ipaddress, signal, struct, textwrap
from collections import defaultdict
from scapy.all import sniff, Dot11, Dot11QoS, UDP, TCP, RadioTap, hexdump, ARP, IP, IPv6
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.snmp import SNMP
from scapy.layers.dot11 import Dot11TKIP, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA
from netaddr import EUI, NotRegisteredError
from base64 import b64decode

import hashlib, pickle
from datetime import datetime, timedelta

_stop_sniffing = threading.Event()
JUICY_LOG_FILE = os.path.join(os.path.dirname(__file__), "juicy_exceptions.log")
_seen_hashes = set()  # global cache of payload hashes
_seen_hash_file = os.path.join(os.path.dirname(__file__), "juicy_seen.pkl")

HANDSHAKE_PCAP = os.path.join(os.path.dirname(__file__), "eapol_handshakes.pcap")

SHOW_BASE64_CONTENT = False

# --- CONFIG ---
IFACE = "wlan1mon"
CHANNELS = [1, 6, 11]
HOP_INTERVAL = 5  # seconds
MANUF_DB_PATH = "/usr/share/wireshark/manuf"

# --- Globals ---
_seen_hashes = set()
_seen_beacons = set()
current_channel = None
_vendor_cache = {}
_manuf_db = {}
_session_flows = {}  # Stores flow data (counts, timestamps)
FLOW_TTL = 900  # seconds; flows idle longer than this are periodically expired
_last_flow_sweep = 0.0  # monotonic timestamp of last _session_flows cleanup
FLOW_SWEEP_INTERVAL = 60  # seconds between sweeps
_beacon_cache = {}        # The empty beacon storage
_written_bssids = set()   # The empty history of saved PCAPs
_pending_beacon_bssids = set()  # BSSIDs seen in EAPOL before their beacon arrived
_eapol_msg_seen = {}      # (src, key_num, replay_counter) -> count, for RETX detection (bounded)
PRINT_COOLDOWN = timedelta(seconds=30)  # Print updates every 30s
BORING_PORTS = {
    #53,     # Standard DNS
    443,    # QUIC (Encrypted Web, e.g., Google)
    3478,   # STUN (WebRTC for VOIP/Video calls)
    123,    # NTP (Network Time Protocol)
}

# -----------------------
# Vendor (OUI) lookup
# -----------------------
def load_manuf_db(path=MANUF_DB_PATH):
    global _manuf_db
    if not os.path.exists(path):
        print(f"[!] manuf DB not found at {path}. OUI fallback disabled.", file=sys.stderr)
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("#") or not line.strip(): continue
                parts = line.strip().split(None, 2)
                if len(parts) >= 2:
                    _manuf_db[parts[0].upper()] = parts[-1].strip()
    except Exception as e:
        print(f"[!] Failed to load manuf DB: {e}", file=sys.stderr)
    else:
        print(f"[*] Loaded {len(_manuf_db)} OUI entries from manuf DB.", file=sys.stderr)

def get_manufacturer(mac):
    if not mac:
        return "N/A"
    if mac in _vendor_cache:
        return _vendor_cache[mac]
    # Semantic classification takes precedence over OUI/manuf lookup:
    # well-known broadcast/multicast groups would otherwise be displayed as
    # raw OUI text (e.g. "OUI:01:00:5E" for IPv4 mDNS 224.0.0.251).
    m = mac.lower()
    if m == "ff:ff:ff:ff:ff:ff":
        return "<Bcast>"
    if m.startswith("33:33"):
        return "<Mcast6>"
    if m.startswith("01:00:5e"):
        return "<Mcast4>"
    try:
        first_octet = int(mac.split(":")[0], 16)
        is_multicast = bool(first_octet & 0x01)  # I/G bit
        locally_administered = bool(first_octet & 0x02)  # U/L bit
        if locally_administered and not is_multicast:
            return "<Random>"
    except (ValueError, IndexError):
        pass
    vendor = None
    try:
        e = EUI(mac)
        reg = e.oui.registration()
        if reg and hasattr(reg, "org"):
            vendor = reg.org
    except (NotRegisteredError, Exception):
        vendor = None
    if not vendor and _manuf_db:
        m = mac.upper()
        for prefix in (m[:14], m[:10], m[:8]):
            if prefix in _manuf_db:
                vendor = _manuf_db[prefix]
                break
    if not vendor:
        parts = mac.split(":")
        vendor = f"OUI:{':'.join(parts[:3]).upper()}" if len(parts) >= 3 else "Unknown"
    final = vendor[:18] + ("..." if len(vendor) > 18 else "")
    _vendor_cache[mac] = final
    return final

# -----------------------
# Channel Hopping
# -----------------------
def set_channel(ch):
    """
    Sets the channel for the IFACE. (For sequential, single-thread design).
    Returns True on success, False on failure.
    current_channel is only updated after the channel change has succeeded.
    """
    global current_channel

    # We REMOVED preexec_fn. We want Ctrl+C to be handled
    # by our main signal_handler.
    # NOTE: returncode must be checked; a completed subprocess with a
    # non-zero exit still means the channel change failed.
    try:
        if subprocess.run(["iw", "dev", IFACE, "set", "channel", str(ch)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=2).returncode == 0:
            current_channel = ch
            return True
    except Exception:
        pass  # iw missing or timed out; fall through to iwconfig

    try:
        if subprocess.run(["iwconfig", IFACE, "channel", str(ch)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=2).returncode == 0:
            current_channel = ch
            return True
    except Exception as e:
        # If we're stopping, don't print an error
        if not _stop_sniffing.is_set():
            print(f"[!] Failed to set channel {ch}: {e}", file=sys.stderr)
        return False

    # Both commands ran but neither succeeded
    if not _stop_sniffing.is_set():
        print(f"[!] Failed to set channel {ch} on {IFACE}", file=sys.stderr)
    return False

def signal_handler(sig, frame):
    """
    Catches Ctrl+C (SIGINT) and sets our global stop flag 
    instead of crashing the program.
    """
    if not _stop_sniffing.is_set():
        print("\n[*] Ctrl+C pressed. Stopping gracefully after this hop...")
        _stop_sniffing.set()
# -----------------------
# Helpers
# -----------------------

def reverse_dns_to_ipv6(name):
    """
    Convert a reverse DNS IPv6 name (like 'B.E.4.E.0.B.E.F.F.F.0.2.6.7.8.D.0.0...ip6.arpa.')
    into a normal IPv6 address (like 'fe80::d876:20ff:feb0:e4eb').
    """
    try:
        if not name.lower().endswith('.ip6.arpa.'):
            return name  # not a reverse IPv6 record
        # Strip suffix and dots, reverse nibble order
        nibbles = name[:-10].split('.')  # remove '.ip6.arpa.'
        nibbles.reverse()
        # Join into groups of 4 hex digits (standard IPv6 hextets)
        ipv6 = ':'.join(
            ''.join(nibbles[i:i+4])
            for i in range(0, len(nibbles), 4)
        )
        # Compress address (remove leading zeros, :: for zero runs)
        import ipaddress
        return str(ipaddress.IPv6Address(ipv6))
    except Exception:
        return name  # fallback if parsing fails

def decode_netbios_name(encoded):
    """
    Decode a NetBIOS-style name (A–P encoding) into its 16-byte ASCII form.
    Keeps raw 16-byte structure for suffix extraction, but trims padding for display.
    """
    try:
        encoded = encoded.strip().strip('.')
        name_bytes = bytearray()
        for i in range(0, len(encoded), 2):
            if i + 1 >= len(encoded):
                break
            high = ord(encoded[i]) - ord('A')
            low = ord(encoded[i + 1]) - ord('A')
            name_bytes.append((high << 4) | low)

        decoded = name_bytes.decode('ascii', errors='ignore')

        # Return the full 16-byte decoded string for suffix handling,
        # but provide a trimmed version for printing later.
        return decoded
    except Exception:
        return encoded

def interpret_netbios_suffix(code):
    """Return a human-readable label for the NetBIOS suffix byte."""
    table = {
        0x00: "Workstation Service / Domain name",
        0x03: "Messenger service",
        0x06: "RAS Server Service",
        0x20: "File Server Service",
        0x21: "RAS client",
        0x1B: "Domain Master Browser",
        0x1C: "Domain Controllers",
        0x1D: "Master Browser (local subnet)",
        0x1E: "Browser Election",
        0x1F: "NetDDE service",
        0xBE: "Network Monitor Agent",
    }
    return table.get(code, f"Unknown (0x{code:02X})")

def log_juicy_exception(meta, payload):
    """
    Save unhandled / unknown packets with metadata and hex dump.
    Skips duplicates (based on SHA1 of payload + key metadata).
    """
    try:

        if not isinstance(payload, (bytes, bytearray)):
            # If it's not bytes (e.g., a str), convert it to its
            # string representation, then encode it to bytes.
            payload = bytes(str(payload), 'utf-8', errors='ignore')

        # Compute a short hash signature for deduplication
        key = f"{meta.get('src','')}-{meta.get('dst','')}-{meta.get('ports','')}".encode()
        sig = hashlib.sha1(key + payload).hexdigest()

        # Skip if we've already seen this payload
        if sig in _seen_hashes:
            return
        _seen_hashes.add(sig)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"\n{'='*80}\n[{timestamp}] JUICY EXCEPTION\n"
        header += " | ".join(f"{k}:{v}" for k, v in meta.items()) + "\n"
        header += f"Hash:{sig}\n"
        header += "-"*80 + "\n"

        # Produce a clean hex dump
        hex_lines = []
        for i in range(0, len(payload), 16):
            chunk = payload[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")

        with open(JUICY_LOG_FILE, "a") as f:
            f.write(header + "\n".join(hex_lines) + "\n")

    except Exception as e:
        print(f"[!] Failed to log juicy exception: {e}", file=sys.stderr)

def load_seen_hashes():
    global _seen_hashes
    if os.path.exists(_seen_hash_file):
        try:
            with open(_seen_hash_file, "rb") as f:
                _seen_hashes = pickle.load(f)
        except Exception:
            _seen_hashes = set()

def save_seen_hashes():
    try:
        with open(_seen_hash_file, "wb") as f:
            pickle.dump(_seen_hashes, f)
    except Exception as e:
        print(f"[!] Could not save seen hashes: {e}")

# -----------------------
# Protocol parsers
# -----------------------
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM", 9: "FORCERENEW"
}

def parse_dhcpv4_options_from_payload(raw, line_wrap=110):
    """
    Parse a DHCP packet's options and extract interesting fields.
    Scans for strings inside known text options, unknown options (like 81),
    and after the 0xFF (end option) marker.
    """
    if not raw or len(raw) < 240:
        return None

    parsed = {}
    try:
        cookie_index = raw.find(b"\x63\x82\x53\x63")
        if cookie_index == -1:
            return None
        options_data = raw[cookie_index + 4:]

        # This set will store ALL unique strings we find
        all_found_strings = set()

        i = 0
        while i < len(options_data):
            opt_type = options_data[i]
            if opt_type == 0xFF:  # End option
                i += 1
                break
            if opt_type == 0:  # Pad option
                i += 1
                continue
            if i + 1 >= len(options_data):
                break # Malformed, no length byte
            
            opt_len = options_data[i + 1]
            
            # --- THIS IS THE FIX ---
            # Check if the *entire* option (header + data) fits in the packet
            if i + 2 + opt_len > len(options_data):
                # The option claims to be longer than the remaining data.
                # This is a malformed packet. We cannot parse this option.
                # Stop parsing options entirely. The remainder will be scanned later.
                break 
            
            # If we are here, the option is *not* truncated
            opt_val = options_data[i + 2:i + 2 + opt_len]

            # --- Now, parse the opt_val we just read ---
            
            if opt_type == 53 and opt_len == 1:  # DHCP message type
                if opt_val:
                    msg_types = {
                        1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                        5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"
                    }
                    parsed["msg_type"] = msg_types.get(opt_val[0], f"Unknown({opt_val[0]})")

            elif opt_type == 6 and opt_len % 4 == 0:  # DNS servers
                dns_servers = []
                for j in range(0, opt_len, 4):
                    if j + 4 <= len(opt_val): # Bounds check
                        ip = ".".join(str(b) for b in opt_val[j:j + 4])
                        dns_servers.append(ip)
                if dns_servers:
                    parsed["dns_servers"] = dns_servers

            elif opt_type == 12:  # Host Name
                hostname = opt_val.decode("ascii", "ignore")
                parsed.setdefault("hostnames", []).append(hostname)
                all_found_strings.add(hostname)
            
            elif opt_type == 60:  # Vendor Class Identifier
                vclass = opt_val.decode("ascii", "ignore")
                parsed.setdefault("vendor_classes", []).append(vclass)
                all_found_strings.add(vclass)
            
            elif opt_type == 15:  # Domain Name
                domain = opt_val.decode("ascii", "ignore")
                parsed["domain_name"] = domain
                all_found_strings.add(domain)

            elif opt_type == 81 and opt_len > 3:
                fqdn = opt_val[3:].decode("ascii", "ignore")
                parsed["fqdn"] = fqdn
                all_found_strings.add(fqdn)

            else:
                m_generic = re.findall(rb"[ -~]{6,}", opt_val)
                for s_bytes in m_generic:
                    try:
                        s_str = s_bytes.decode("ascii", "ignore").strip()
                        if s_str: 
                            all_found_strings.add(s_str)
                    except Exception:
                        pass 

            # --- And *now* we increment i to move to the *next* option ---
            i += 2 + opt_len
            
        # --- The loop is over. Now we scan the remainder (post-option ascii)---
        # 'i' is now at the start of the post-option data (or at the end)
        remainder = options_data[i:]
        if remainder:
            for m in re.findall(rb"[ -~]{4,}", remainder):
                try:
                    s = m.decode("utf-8", errors="ignore").strip()
                    if s:
                        all_found_strings.add(s)
                except Exception:
                    pass

        # --- Final Step: Clean up and add the consolidated list ---
        if "hostnames" in parsed:
            all_found_strings.difference_update(parsed["hostnames"])
        if "vendor_classes" in parsed:
            all_found_strings.difference_update(parsed["vendor_classes"])
        if "domain_name" in parsed:
            all_found_strings.discard(parsed["domain_name"])
        if "fqdn" in parsed:
            all_found_strings.discard(parsed["fqdn"])

        if all_found_strings:
            cleaned_strings = {s.strip() for s in all_found_strings if s.strip()}
            if cleaned_strings:
                parsed["found_strings"] = sorted(list(cleaned_strings))
        
        # --- Summary line ---
        if "msg_type" not in parsed:
            parsed["msg_type"] = "UNKNOWN"
            
        summary_parts = [f"DHCP: msg_type={parsed['msg_type']}"]
        if "hostnames" in parsed:
            summary_parts.append(f"Hostnames: {parsed['hostnames']}")
        # --- Add FQDN to summary ---
        if "fqdn" in parsed:
            summary_parts.append(f"FQDN: {parsed['fqdn']}")
        if "vendor_classes" in parsed:
            summary_parts.append(f"Vendor: {parsed['vendor_classes']}")
        if "dns_servers" in parsed:
            summary_parts.append(f"DNS: {parsed['dns_servers']}")
        if "found_strings" in parsed:
            summary_parts.append(f"Strings: {parsed['found_strings']}")

        summary = " | ".join(summary_parts)
        if len(summary) > line_wrap:
            summary = re.sub(
                r"(.{1," + str(line_wrap) + r"})(?:\s+|$)",
                "\\1\n    ",
                summary
            )
        parsed["__summary__"] = summary

    except Exception as e:
        # print(f"[debug] DHCPv4 parse error: {e}") # Uncomment to debug
        return None

    return parsed

def parse_ssdp_payload(raw, max_width=120):
    """
    Parse SSDP (Simple Service Discovery Protocol) payloads and produce
    a readable summary, auto-wrapping long lines at max_width characters.
    """
    try:
        txt = raw.decode('utf-8', errors='ignore')
    except Exception:
        return None

    low = txt.lower()
    if "m-search" in low or "notify" in low or "http/1.1" in low:
        out = {}

        # Split into lines and extract the first request/status line separately
        lines = re.split(r'\r?\n', txt)
        if lines and lines[0].strip():
            out["__firstline__"] = lines[0].strip()

        # Parse the rest of the headers case-insensitively
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip().upper()] = v.strip()

        # Compose a nice human-readable summary
        parts = []
        if "__firstline__" in out:
            fl = out["__firstline__"].upper()
            parts.append(out["__firstline__"])
            if fl.startswith("M-SEARCH"):
                out["__msgtype__"] = "SEARCH"
            elif fl.startswith("NOTIFY"):
                out["__msgtype__"] = "ADVERT"
            elif fl.startswith("HTTP/1.1"):
                out["__msgtype__"] = "RESPONSE"

        # Include common SSDP headers in consistent order
        for key in (
            "HOST", "MAN", "ST", "NT", "MX",
            "SERVER", "USER-AGENT", "USN", "LOCATION",
            "CACHE-CONTROL", "EXT"
        ):
            if key in out:
                parts.append(f"{key}={out[key]}")

        # Join all parts into a single summary string
        summary = " | ".join(parts)

        # 🔹 Auto-wrap long lines at max_width
        if len(summary) > max_width:
            wrapped = []
            line = ""
            for seg in summary.split(" | "):
                # +3 accounts for the " | " separator when joining
                if len(line) + len(seg) + 3 > max_width:
                    wrapped.append(line.strip())
                    line = seg
                else:
                    line += (" | " if line else "") + seg
            if line:
                wrapped.append(line.strip())
            summary = "\n    ".join(wrapped)  # indent wrapped lines for readability

        out["__summary__"] = summary
        return out

    return None

def parse_mdns_payload(raw):
    try:
        dns = DNS(raw)
    except Exception:
        return None
    if not (dns.qdcount or dns.ancount or dns.arcount or dns.nscount):
        return None

    parsed = {'questions': [], 'answers': []}

    # ---- Questions ----
    for i in range(dns.qdcount):
        q = dns.qd[i]
        parsed['questions'].append({
            'qname': q.qname.decode('utf-8', errors='ignore') if hasattr(q, 'qname') else '?',
            'qtype': q.qtype
        })

    # ---- Collect all RR sections: Answer + Authority + Additional ----
    rr_sections = []
    for secname, count, accessor in [
        ('an', dns.ancount, lambda i: dns.an[i]),
        ('ns', dns.nscount, lambda i: dns.ns[i]),
        ('ar', dns.arcount, lambda i: dns.ar[i]),
    ]:
        for i in range(count):
            try:
                rr = accessor(i)
            except Exception:
                continue
            entry = {
                'rrname': rr.rrname.decode('utf-8', errors='ignore') if hasattr(rr, 'rrname') else '?',
                'type': getattr(rr, 'type', '?'),
            }

            if rr.type == 16:  # TXT record
                # --- This is the fix for the bug we found earlier ---
                rdata_content = rr.rdata
                if isinstance(rdata_content, list):
                    txt_bytes = b' '.join(rdata_content)
                elif isinstance(rdata_content, (bytes, bytearray)):
                    txt_bytes = rdata_content
                else:
                    txt_bytes = bytes(str(rdata_content), 'utf-8')

                try:
                    txt_str = txt_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    txt_str = repr(txt_bytes)
                # --- End fix ---

                # Values may legitimately contain periods (e.g. hostnames);
                # values end at the space separating TXT character-strings, or \n / \r.
                kvs = re.findall(r"([A-Za-z0-9_]+)=([^\s\n\r]*)", txt_str)
                entry['txt_fields'] = {}
                for k, v in kvs:
                    v = v.strip()
                    if re.match(r"^[A-Za-z0-9+/=]{20,}$", v):
                        try:
                            decoded = b64decode(v)
                            if SHOW_BASE64_CONTENT:
                                entry['txt_fields'][k] = decoded.hex()[:80] + "..."
                            else:
                                entry['txt_fields'][k] = f"[base64:{len(decoded)} bytes]"
                        except Exception:
                            entry['txt_fields'][k] = v
                    else:
                        entry['txt_fields'][k] = v
                entry['rdata'] = txt_str

            # --- 💡 NEW BLOCK TO LOOKUP EDNS0OWN VENDOR 💡 ---
            elif rr.type == 41: # OPT (EDNS) Record
                # Start with the default string representation
                rdata_str = str(rr.rdata)
                try:
                    # EDNS rdata is a list of options
                    if hasattr(rr.rdata, '__iter__'):
                        new_rdata_parts = []
                        for opt in rr.rdata:
                            opt_str = str(opt) # Get the default string for this option

                            # Check if it's the 'EDNS0OWN' object by name
                            if "EDNS0OWN" in opt.__class__.__name__:
                                if hasattr(opt, 'primary_mac'):
                                    mac = opt.primary_mac
                                    # Call our global vendor lookup function
                                    vendor = get_manufacturer(mac)
                                    if vendor:
                                        # Inject the vendor into the string
                                        opt_str = opt_str.replace(mac, f"{mac} ({vendor})")
                            new_rdata_parts.append(opt_str)
                        # Re-join the (potentially modified) list of strings
                        rdata_str = f"[{', '.join(new_rdata_parts)}]"
                except Exception:
                    pass # Fallback to the default rdata_str
                entry['rdata'] = rdata_str
            # --- END NEW BLOCK ---

            else:
                # Generic fallback for other RR types. Structured Scapy RR
                # subclasses (SRV, SOA, MX, NAPTR, DS, SVCB, HTTPS, TSIG, ...)
                # have no `rdata` field; their data lives in their own named
                # fields. Skip raw-rdata extraction for them instead of
                # raising AttributeError('rdata') — which would escape the
                # prn callback and tear down Scapy's sniff socket.
                rdata = getattr(rr, "rdata", None)
                if rdata is None:
                    parsed['answers'].append(entry)
                    continue

                if isinstance(rdata, bytes):
                    rdata_str = rdata.decode('utf-8', errors='ignore')
                else:
                    rdata_str = str(rdata)
                entry['rdata'] = rdata_str

                # Extra heuristic: look for embedded printable strings
                if not re.search(r'[A-Za-z]', rdata_str):
                    m = re.findall(rb"[ -~]{5,}", bytes(rdata) if isinstance(rdata, (bytes, bytearray)) else b"")
                    if m:
                        printable_bits = [x.decode('utf-8', errors='ignore') for x in m]
                        entry['printables'] = printable_bits
                        entry['rdata'] = printable_bits[0] if printable_bits else rdata_str

            parsed['answers'].append(entry)

    # ---- Optional summary ----
    important_fields = ['AppData', 'MediumType', 'QDebugInfo']
    summary_bits = []

    for rr in parsed['answers']:
        if 'txt_fields' in rr:
            for k, v in rr['txt_fields'].items():
                if k in important_fields:
                    summary_bits.append(f"{k}={v}")
        elif 'printables' in rr:
            summary_bits.extend(rr['printables'])

    if summary_bits:
        parsed['__summary__'] = " | ".join(summary_bits)

    return parsed

def parse_dropbox_lansync(raw):
    """Parse Dropbox LAN sync UDP discovery messages (port 17500)."""
    try:
        txt = raw.decode('utf-8', errors='ignore').strip()
        if not txt.startswith('{'):
            return None
        data = json.loads(txt)
        out = {}

        # Extract all keys
        for k, v in data.items():
            out[k] = v

        # Build a concise summary
        summary_parts = []
        if "version" in out:
            summary_parts.append(f"ver={out['version']}")
        if "namespaces" in out:
            summary_parts.append(f"ns={out['namespaces']}")
        if "displayname" in out and out["displayname"]:
            summary_parts.append(f"name=\"{out['displayname']}\"")
        if "host_int" in out:
            summary_parts.append(f"host={out['host_int']}")

        out["__summary__"] = " | ".join(summary_parts)
        return out
    except Exception:
        return None

def parse_dhcpv6_options_from_payload(raw, line_wrap=110):
    """
    Parse DHCPv6 message (msg-type + 3-byte transaction id + options).
    Decodes DUIDs (Client/Server IDs), extracts vendor class text,
    and maps option numbers to human-readable names.
    """

    if not raw or len(raw) < 4:
        return None

    import struct, re

    parsed = {}
    try:
        # DHCPv6 header: 1 byte msg-type, 3 bytes transaction-id
        msg_type = raw[0]
        trans_id = raw[1:4].hex()
        parsed["msg_type_num"] = msg_type
        parsed["trans_id"] = trans_id

        msg_types = {
            1: "SOLICIT", 2: "ADVERTISE", 3: "REQUEST", 4: "CONFIRM",
            5: "RENEW", 6: "REBIND", 7: "REPLY", 8: "RELEASE",
            9: "DECLINE", 10: "RECONFIGURE", 11: "INFORMATION-REQUEST",
            12: "RELAY-FORW", 13: "RELAY-REPL"
        }
        parsed["msg_type"] = msg_types.get(msg_type, f"UNKNOWN({msg_type})")

        # --- Option name map ---
        dhcpv6_opt_names = {
            1: "ClientID", 2: "ServerID", 3: "IA_NA", 4: "IA_TA",
            5: "IAAddr", 6: "OptionRequest", 7: "Preference",
            8: "ElapsedTime", 9: "RelayMsg", 11: "Auth", 12: "Unicast",
            13: "StatusCode", 14: "RapidCommit", 15: "UserClass",
            16: "VendorClass", 17: "VendorOpts", 18: "InterfaceID",
            19: "ReconfMsg", 23: "DNSRecursiveNS", 24: "DomainSearchList",
            25: "IA_PD", 26: "IAPrefix", 31: "SNTPServers", 39: "FQDN"
        }

        # --- Parse options ---
        i = 4
        options = {}
        while i + 4 <= len(raw):
            opt_code, opt_len = struct.unpack_from("!HH", raw, i)
            i += 4
            if i + opt_len > len(raw):
                break
            val = raw[i:i + opt_len]
            i += opt_len
            options.setdefault(opt_code, []).append(val)
        parsed["options_raw"] = options

        # --- Decode DUID ClientID / ServerID ---
        duid_info = []
        for opt_num, label in [(1, "ClientID"), (2, "ServerID")]:
            if opt_num not in options:
                continue
            for duid_bytes in options[opt_num]:
                if len(duid_bytes) < 2:
                    continue
                duid_type = struct.unpack_from("!H", duid_bytes, 0)[0]
                desc = f"DUID(type={duid_type})"
                vendor = None

                if duid_type == 1 and len(duid_bytes) >= 8:
                    hw_type = struct.unpack_from("!H", duid_bytes, 2)[0]
                    ts = struct.unpack_from("!I", duid_bytes, 4)[0]
                    mac_bytes = duid_bytes[8:]
                    mac = ":".join(f"{b:02x}" for b in mac_bytes)
                    if len(mac_bytes) >= 3:
                        vendor = get_manufacturer(mac)
                    desc = f"DUID-LLT(hw={hw_type}, ts={ts}, mac={mac})"
                    if vendor:
                        desc += f" [{vendor}]"

                elif duid_type == 3 and len(duid_bytes) >= 6:
                    hw_type = struct.unpack_from("!H", duid_bytes, 2)[0]
                    mac_bytes = duid_bytes[4:]
                    mac = ":".join(f"{b:02x}" for b in mac_bytes)
                    if len(mac_bytes) >= 3:
                        vendor = get_manufacturer(mac)
                    desc = f"DUID-LL(hw={hw_type}, mac={mac})"
                    if vendor:
                        desc += f" [{vendor}]"

                elif duid_type == 4 and len(duid_bytes) >= 18:
                    uuid_bytes = duid_bytes[2:18]
                    uuid_str = f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-{uuid_bytes[10:16].hex()}"
                    desc = f"DUID-UUID({uuid_str})"

                duid_info.append(f"{label}={desc}")
        if duid_info:
            parsed["duid_info"] = duid_info

        # --- Vendor strings ---
        vendor_strings = []
        for opt_num in (8, 16, 17):
            if opt_num not in options:
                continue
            for val in options[opt_num]:
                for m in re.findall(rb"[ -~]{4,}", val):
                    s = m.decode("utf-8", "ignore").strip()
                    if s:
                        vendor_strings.append(s)
        if vendor_strings:
            parsed["vendor_strings"] = vendor_strings

        # --- Printable ASCII extraction ---
        post_ascii = []
        for optlist in options.values():
            for v in optlist:
                for m in re.findall(rb"[ -~]{4,}", v):
                    try:
                        post_ascii.append(m.decode("utf-8", errors="ignore"))
                    except Exception:
                        post_ascii.append(m.hex())
        if post_ascii:
            parsed["post_ascii"] = sorted(set(post_ascii))

        # --- Replace numeric codes with readable names for display ---
        parsed["options"] = [
            dhcpv6_opt_names.get(num, f"Opt{num}") for num in options.keys()
        ]

        # --- Build summary ---
        summary_parts = [
            f"DHCPv6: msg_type={parsed['msg_type']} trans_id={parsed['trans_id']}"
        ]
        if "duid_info" in parsed:
            summary_parts.append(" | ".join(parsed["duid_info"]))
        if "vendor_strings" in parsed:
            summary_parts.append(f"Vendor={', '.join(parsed['vendor_strings'])}")

        summary = " | ".join(summary_parts)
        if len(summary) > line_wrap:
            import re
            summary = re.sub(r"(.{1," + str(line_wrap) + r"})(?:\s+|$)", "\\1\n   ", summary)

        parsed["__summary__"] = summary

    except Exception:
        return None

    return parsed

def parse_generic_json(raw):
    """
    Tries to find and parse a JSON object anywhere in a UDP payload.
    This is a "catch-all" for unknown proprietary protocols that use JSON.
    """
    try:
        # Find the first '{' and the last '}'
        json_start = raw.find(b'{')
        json_end = raw.rfind(b'}') + 1
        
        if json_start != -1 and json_end != -1 and json_end > json_start:
            txt = raw[json_start:json_end].decode('utf-8', errors='ignore').strip()
            data = json.loads(txt) # Try to parse it
            
            # Success! Let's build a simple summary.
            summary = "Generic JSON: "
            
            # Try to find common keys, but don't fail if they're not there
            if 'model' in data:
                summary += f"model={data['model']} | "
            elif 'body' in data and 'deviceInfo' in data['body'] and 'model' in data['body']['deviceInfo']:
                summary += f"model={data['body']['deviceInfo']['model']} | " # For Omada
            
            if 'ip' in data:
                summary += f"ip={data['ip']} | "
            elif 'body' in data and 'deviceInfo' in data['body'] and 'ip' in data['body']['deviceInfo']:
                 summary += f"ip={data['body']['deviceInfo']['ip']} | " # For Omada

            if 'name' in data:
                summary += f"name={data['name']} | "

            # If no common keys, just show the top-level keys
            if summary == "Generic JSON: ":
                summary += f"Keys={list(data.keys())}"

            return {"__summary__": summary}
        
    except Exception:
        # It looked like JSON, but failed to parse. Not a problem.
        return None
    return None

def parse_snmp_payload(pkt):
    """
    Parses an SNMP packet (UDP 161/162) to extract the
    version and, most importantly, the community string.
    """
    try:
        # We need the full packet to get the Scapy layer
        if not pkt.haslayer(SNMP):
            return None

        snmp_layer = pkt[SNMP]

        # The .val is needed to get the integer/bytes
        version = getattr(snmp_layer, 'version', None)
        version = getattr(version, 'val', 'unknown')

        community = getattr(snmp_layer, 'community', None)
        community = getattr(community, 'val', b'unknown')

        # Decode community string from bytes to a printable string
        community_str = community.decode('utf-8', 'ignore')

        summary = f"SNMP (v{version}): Community='{community_str}'"

        # Highlight the jackpot
        if community_str == 'public':
            summary += " [! VULNERABLE DEFAULT !]"

        return {"__summary__": summary}

    except Exception as e:
        # print(f"[debug] SNMP parse error: {e}")
        return None
# -----------------------
# EAPOL helpers
# -----------------------
_EAPOL_MSG_MAX = 128  # bound on tracked (src,key_num,replay_counter) entries

def classify_eapol_key(eapol_key, src):
    """
    Classify a WPA 4-way-handshake EAPOL-Key frame from its KeyInfo fields.
    Returns (label, is_retx) where label is 'M1'..'M4' or 'M?' if the
    available fields are ambiguous. Retransmissions are identified by a
    repeated (src, key_num, key_replay_counter) combination.
    """
    key_num = 0
    try:
        key_num = int(eapol_key.guess_key_number())
    except Exception:
        key_num = 0
    if key_num not in (1, 2, 3, 4):
        label = "UNCLASSIFIED"
    else:
        label = f"M{key_num}"

    # Retransmission: same source, same message number, same replay counter
    rc = getattr(eapol_key, "key_replay_counter", None)
    is_retx = False
    if key_num and rc is not None:
        sig = (src, key_num, rc)
        n = _eapol_msg_seen.get(sig, 0)
        _eapol_msg_seen[sig] = n + 1
        is_retx = n > 0
        # keep the state bounded
        if len(_eapol_msg_seen) > _EAPOL_MSG_MAX:
            try:
                oldest = next(iter(_eapol_msg_seen))
                _eapol_msg_seen.pop(oldest)
            except Exception:
                pass
    return label, is_retx

# -----------------------
# Packet handler
# -----------------------
def frame_direction(dot11):
    to_ds = bool(dot11.FCfield & 0x1)
    from_ds = bool(dot11.FCfield & 0x2)
    if to_ds and not from_ds:
        return "STA→AP"
    elif from_ds and not to_ds:
        return "AP→STA"
    elif not to_ds and not from_ds:
        return "STA↔STA"
    else:
        return "WDS"

def packet_handler(pkt):
    # --- Global declared ONCE at the top ---
    global _session_flows, _beacon_cache, _written_bssids

    if not pkt.haslayer(Dot11):
        return
    dot11 = pkt[Dot11]
    # --- NEW: SILENT BEACON COLLECTOR ---
    # We need to save Beacons to the PCAP so Aircrack knows the SSID (Network Name).
    # But we don't want to analyze or print them.
    if dot11.type == 0 and dot11.subtype == 8: # Type 0 (Mgmt), Subtype 8 (Beacon)
        bssid = dot11.addr3
        _beacon_cache[bssid] = pkt
        # If an EAPOL frame already referenced this BSSID but no beacon was
        # cached at the time, write the (latest) beacon now — exactly once.
        if bssid in _pending_beacon_bssids and bssid not in _written_bssids:
            try:
                from scapy.all import wrpcap
                wrpcap(HANDSHAKE_PCAP, pkt, append=True)
                _written_bssids.add(bssid)
                print(f"[*] Late beacon for {bssid} written to handshake PCAP.")
            except Exception as e:
                print(f"[!] Failed to write late beacon for {bssid}: {e}", file=sys.stderr)
        return
    # ------------------------------------
    if dot11.type != 2:
        return # We only want Data frames

    subtype = dot11.subtype
    frame_type = dot11.type
    direction = frame_direction(dot11)

    src = getattr(dot11, "addr2", None)
    dst = getattr(dot11, "addr1", None)
    bssid = getattr(dot11, "addr3", None) # Helper to identify the network
    if not src or not dst:
        return

    src_vendor = get_manufacturer(src)
    dst_vendor = get_manufacturer(dst)
    ch = current_channel if current_channel is not None else "?"

    # --- CRITICAL MISSING PART: Extract IP Addresses ---
    src_ip, dst_ip = "", ""
    if pkt.haslayer(IP):
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
    # ---------------------------------------------------

    # Predefine optional protocol lists so they're always safe to reference
    qs = []
    ans = []
    # --- Flag to track if we've parsed this packet ---
    found_any = False
    intel_str = ""
    flow_key = f"{src}|{dst}"

    # Periodic idle-flow expiry: _session_flows would otherwise grow without
    # bound on busy networks. Sweeps at most once per FLOW_SWEEP_INTERVAL,
    # removing only entries idle longer than FLOW_TTL (checked via last_seen,
    # so active flows are never dropped). Time-based, not per-packet, and no
    # thread is needed.
    global _last_flow_sweep
    now_mono = time.monotonic()
    if now_mono - _last_flow_sweep >= FLOW_SWEEP_INTERVAL:
        _last_flow_sweep = now_mono
        cutoff = datetime.now() - timedelta(seconds=FLOW_TTL)
        expired = [k for k, fd in _session_flows.items()
                   if fd.get('last_seen', cutoff) < cutoff]
        for k in expired:
            del _session_flows[k]

    # --- BLOCK 1: HANDLE UDP PACKETS ---
    if pkt.haslayer(UDP):
        found_any = True # Mark as found
        udp = pkt[UDP]
        sport, dport = udp.sport, udp.dport
        payload = bytes(udp.payload)

        now = datetime.now()

        # --- SMART DE-DUPLICATION KEY ---
        flow_key = f"{src}|{dst}|{sport}|{dport}|{src_ip}|{dst_ip}"
        if sport in (5353, 5355, 1900, 17500) or dport in (5353, 5355, 1900, 17500):
            payload_hash = hashlib.md5(payload).hexdigest()
            # Include src/dst so different devices sending identical payloads
            # stay distinct flows (dst separates multicast vs unicast queries)
            flow_key = f"DISCOVERY|{src}|{dst}|{sport}|{dport}|{payload_hash}"
        # --- END SMART KEY ---

        flow_data = _session_flows.get(flow_key)
        show_packet = False

        if not flow_data:
            flow_data = {
                'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now
            }
            _session_flows[flow_key] = flow_data
            show_packet = True
        else:
            flow_data['count'] += 1
            flow_data['last_seen'] = now
            if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                show_packet = True
                flow_data['last_printed'] = now
            else:
                show_packet = False

        if not show_packet:
            return  # Silently drop duplicate

        #pkt.show()

        # --- Initialize all parser vars to None for this packet ---
        dhcp_info = ssdp_info = mdns_info = dropbox_info = dhcpv6_info = json_info = netbios_name = snmp_info = fingerprint_intel = dns_info = None
        netbios_ips = []

        # --- Run Parsers ---
        if sport in (67,68) or dport in (67,68):
            dhcp_info = parse_dhcpv4_options_from_payload(payload)
        elif sport == 53 or dport == 53:
            try:
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    # QR=0 is a Query (Request)
                    if dns.qr == 0 and dns.qd:
                        qname = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.')
                        dns_info = f"DNS Query: {qname}"

                    # QR=1 is an Answer (Response)
                    elif dns.qr == 1 and dns.an:
                        # Get the name being resolved
                        rrname = dns.an.rrname.decode('utf-8', 'ignore').rstrip('.')
                        # Get the answer data (IP or alias)
                        rdata = dns.an.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode('utf-8', 'ignore')
                        dns_info = f"DNS Answer: {rrname} -> {rdata}"
            except Exception:
                pass
        if sport in (546,547) or dport in (546,547):
            dhcpv6_info = parse_dhcpv6_options_from_payload(payload)
        if sport == 1900 or dport == 1900:
            ssdp_info = parse_ssdp_payload(payload)
        if sport in (5353,5355) or dport in (5353,5355):
            mdns_info = parse_mdns_payload(payload)
        if sport == 17500 or dport == 17500:
            dropbox_info = parse_dropbox_lansync(payload)
        elif sport == 29810 or dport == 29810:
            json_info = parse_generic_json(payload)
        elif sport == 137 or dport == 137:
            m = re.search(rb'([A-P]{2,})(?:\x00|$)', payload)
            if m:
                try:
                    encoded_name = m.group(1).decode('ascii', errors='ignore')
                    decoded_raw = decode_netbios_name(encoded_name)
                    if len(decoded_raw) >= 16:
                        name = decoded_raw[:15].strip()
                        suffix_byte = ord(decoded_raw[15])
                    else:
                        name = decoded_raw.strip()
                        suffix_byte = 0
                    suffix_desc = interpret_netbios_suffix(suffix_byte)
                    netbios_name = f"{name} [{suffix_desc}]"
                    ips = re.findall(rb'\x00\x20\x00\x01.{10}((?:\d{1,3}\.){3}\d{1,3})', payload)
                    if ips:
                        netbios_ips = [ip.decode('ascii') for ip in ips]
                except Exception:
                    netbios_name = None
                    netbios_ips = []

        elif sport == 138 or dport == 138:
            fingerprint_intel = "NetBIOS DGM: Workgroup Broadcast"

            # 1. Try to decode the Header Names (The A-P Encoded stuff)
            # We look for sequences of A-P characters (NetBIOS encoding)
            # This handles the stuff at offset 0x0010 and 0x0030
            encoded_matches = re.findall(rb'([A-P]{16,})', payload)
            decoded_names = []
            for enc in encoded_matches:
                try:
                    d = decode_netbios_name(enc.decode('ascii'))
                    # Clean up the result (remove padding/non-printable)
                    clean = d.strip()
                    # Decode special suffixes (like the <01> or <20>) if possible
                    if len(d) >= 16:
                        suffix = ord(d[15])
                        # Only show suffix if it's interesting
                        suffix_desc = interpret_netbios_suffix(suffix)
                        clean = d[:15].strip()
                        if "Unknown" not in suffix_desc:
                            clean += f"<{suffix_desc}>"

                    if clean and clean not in decoded_names:
                        decoded_names.append(clean)
                except Exception:
                    pass

            if decoded_names:
                fingerprint_intel += f" | Names: {decoded_names}"

            # 2. Scan for Cleartext Strings (The Footer stuff)
            # This handles \MAILSLOT\BROWSE and the cleartext Hostname/Domain
            m = re.findall(rb"[ -~]{5,}", payload)
            if m:
                clean_strings = []
                for s in m:
                    s_str = s.decode('utf-8', 'ignore')
                    # Filter out the encoded blobs we already handled
                    if re.match(r'^[A-P]{16,}$', s_str):
                        continue
                    # Filter out standard headers
                    if "MAILSLOT" in s_str or "BROWSE" in s_str:
                        continue
                    if s_str not in clean_strings and s_str not in decoded_names:
                        clean_strings.append(s_str)

                if clean_strings:
                    fingerprint_intel += f" | Data: {clean_strings}"
        elif sport == 3478 or dport == 3478:
            fingerprint_intel = "STUN: WebRTC/VoIP NAT Traversal"

        elif sport == 3544 or dport == 3544:
            fingerprint_intel = "Teredo: Windows IPv6 Tunnel"

        elif sport == 5350 or dport == 5350:
            fingerprint_intel = "PCP: Port Control Protocol"

        elif sport == 5351 or dport == 5351:
            fingerprint_intel = "NAT-PMP: Apple Port Mapping"

        elif sport in (161, 162) or dport in (161, 162):
            # We pass the *full packet* (pkt) because Scapy has
            # already layered it for us.
            snmp_info = parse_snmp_payload(pkt)

        # --- Start Printing UDP Packet ---
        print("="*80)
        count = flow_data['count']
        first_seen_str = flow_data['first_seen'].strftime("%H:%M:%S")
        last_seen_str = flow_data['last_seen'].strftime("%H:%M:%S")
        header_str = f"[Seen: {count}x] [First: {first_seen_str}] [Last: {last_seen_str}] "
        print(f"{header_str}Type:{frame_type} Subtype:0x{subtype:02x} | Dir:{direction} | CH:{ch}")
        print(f"{src} ({src_vendor}) → {dst} ({dst_vendor}) | UDP {sport}->{dport}")

        parsed_protocol = False

        if netbios_name:
            parsed_protocol = True
            print(f"→ NetBIOS Name: {netbios_name}")
            if netbios_ips:
                print(f"    Resolved IPs: {netbios_ips}")
        if dns_info:
            parsed_protocol = True
            print(f"→ {dns_info}")
            flow_data['intel'] = dns_info # Save for final report
        if snmp_info:
            found_any = True
            summary_str = snmp_info.get('__summary__', 'SNMP: ?')
            print(f"→ {summary_str}")
            flow_data['intel'] = summary_str # Save for final report
        if dhcp_info:
            parsed_protocol = True
            print(f"→ {dhcp_info.get('__summary__','DHCP: ?')}")
        if dhcpv6_info:
            parsed_protocol = True
            print(f"→ {dhcpv6_info.get('__summary__', 'DHCPv6: ?')}")
            if 'options' in dhcpv6_info:
                print(f"    Options: {dhcpv6_info['options']}")
        if ssdp_info:
            parsed_protocol = True
            print(f"→ SSDP: {ssdp_info.get('__summary__','')}")
            for k in ("LOCATION","SERVER","USN"):
                if k in ssdp_info:
                    print(f"    {k}: {ssdp_info[k]}")
        if mdns_info:
            parsed_protocol = True
            qs = mdns_info.get('questions', [])
            ans = mdns_info.get('answers', [])
            if '__summary__' in mdns_info:
                print(f"→ mDNS: {mdns_info['__summary__']}")
            else:
                print(f"→ mDNS: {len(qs)} Q, {len(ans)} A")
            for q in qs[:17]:
                try:
                    print(f"    Q: {q.get('qname', '?')} (type {q.get('qtype', '?')})")
                except Exception:
                    print("    Q: [parse error]")
            for a in ans[:17]:
                try:
                    rrname = a.get('rrname', '?')
                    if rrname.lower().endswith('.ip6.arpa.'):
                        rrname = reverse_dns_to_ipv6(rrname)
                    rdata = a.get('rdata', '?')
                    if isinstance(rdata, str) and re.fullmatch(r'[A-P]{2,}', rdata.replace('.', '')):
                        rdata = decode_netbios_name(rdata)
                    print(f"    A: {rrname} → {rdata}")
                except Exception as e:
                    print(f"    A: [parse error: {e}]")
        if dropbox_info:
            parsed_protocol = True
            print(f"→ Dropbox LAN Sync: {dropbox_info.get('__summary__','')}")
        if json_info:
            parsed_protocol = True
            print(f"→ {json_info.get('__summary__','Generic JSON')}")
        if fingerprint_intel:
            found_any = True
            print(f"→ {fingerprint_intel}")
            flow_data['intel'] = fingerprint_intel # Save for final report

        if not parsed_protocol:
            if sport in BORING_PORTS or dport in BORING_PORTS:
                return  # Silently drop boring packets

            json_info = parse_generic_json(payload)
            if json_info:
                parsed_protocol = True
                print(f"→ {json_info.get('__summary__','Generic JSON (on unknown port)')}")
            else:
                print("→ (no parsed juicy fields; showing raw hex payload)")
                meta = {
                    "ch": ch, "dir": direction, "src": src, "src_vendor": src_vendor,
                    "dst": dst, "dst_vendor": dst_vendor, "ports": f"{sport}->{dport}"
                }
                log_juicy_exception(meta, payload)

        print("-"*80)
        try:
            print(hexdump(payload, dump=True))
        except Exception as e:
            print(f"[!] hexdump error: {e}")
        print("="*80)

    # --- BLOCK 2: HANDLE ARP PACKETS ---
    elif pkt.haslayer(ARP):
        found_any = True # Mark as found
        arp = pkt[ARP]

        if arp.op == 2: # 2 == "is-at" (a reply)
            ip = arp.psrc
            mac = arp.hwsrc

            now = datetime.now()
            flow_key = f"ARP|{ip}|{mac}"

            flow_data = _session_flows.get(flow_key)
            show_packet = False

            if not flow_data:
                flow_data = {
                    'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now
                }
                _session_flows[flow_key] = flow_data
                show_packet = True
            else:
                flow_data['count'] += 1
                flow_data['last_seen'] = now
                if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                    show_packet = True
                    flow_data['last_printed'] = now
                else:
                    show_packet = False

            if show_packet:
                #pkt.show()
                print("="*80)
                count = flow_data['count']
                first_seen_str = flow_data['first_seen'].strftime("%H:%M:%S")
                last_seen_str = flow_data['last_seen'].strftime("%H:%M:%S")

                header_str = f"[Seen: {count}x] [First: {first_seen_str}] [Last: {last_seen_str}] "
                print(f"{header_str}Type:ARP Subtype:Reply | Dir:{direction} | CH:{ch}")

                print(f"{mac} ({get_manufacturer(mac)}) ⇔ {ip}")
                print("→ ARP Reply (is-at): Device IP/MAC mapping confirmed.")
                print("="*80)

    # --- BLOCK 3: HANDLE TCP PACKETS ---
    elif pkt.haslayer(TCP):
        found_any = True
        tcp = pkt[TCP]
        sport, dport = tcp.sport, tcp.dport
        payload = bytes(tcp.payload)

        now = datetime.now()

        # --- TCP De-duplication Key ---
        # Include IPs in the key if we have them (extracted at top of function)
        flow_key = f"{src}|{dst}|{sport}|{dport}|{src_ip}|{dst_ip}"

        if sport in BORING_PORTS or dport in BORING_PORTS:
            # For encrypted traffic, hash the payload to detect duplicates
            payload_hash = hashlib.md5(payload[:128]).hexdigest()
            flow_key = f"TCP-ENCRYPTED|{src}|{dst}|{sport}|{dport}|{payload_hash}"

        flow_data = _session_flows.get(flow_key)
        show_packet = False

        if not flow_data:
            flow_data = {
                'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now,
                'intel': "Initializing TCP..." # Placeholder
            }
            _session_flows[flow_key] = flow_data
            show_packet = True
        else:
            flow_data['count'] += 1
            flow_data['last_seen'] = now
            if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                show_packet = True
                flow_data['last_printed'] = now
            else:
                show_packet = False

        # --- Parse TCP "Juice" (Generate summary for Report AND Print) ---
        summary_str = ""
        if tcp.flags.S:
            summary_str = "TCP SYN: Connection attempt"
        elif tcp.flags.R:
            summary_str = "TCP RST: Connection reset"
        elif tcp.flags.PA:
            summary_str = "TCP PSH+ACK: Data packet"
        elif tcp.flags.A:
            summary_str = "TCP ACK: Keep-alive / Ack"
        else:
            summary_str = f"TCP Packet (Flags: {tcp.flags})"

        # FIX 1: Always scan for text if payload exists (regardless of flags)
        if payload:
            m = re.findall(rb"[ -~]{10,}", payload)
            if m:
                printable_text = " ".join([s.decode('utf-8', 'ignore') for s in m])
                summary_str += f" | Text: \"{printable_text[:75]}...\""

        # FIX 2: Save the summary to flow_data so the Final Report isn't empty
        flow_data['intel'] = summary_str

        if not show_packet:
            return

        print("="*80)
        count = flow_data['count']
        first_seen_str = flow_data['first_seen'].strftime("%H:%M:%S")
        last_seen_str = flow_data['last_seen'].strftime("%H:%M:%S")

        header_str = f"[Seen: {count}x] [First: {first_seen_str}] [Last: {last_seen_str}] "
        print(f"{header_str}Type:TCP Subtype:Data | Dir:{direction} | CH:{ch}")

        # FIX 3: Print IPs (src_ip/dst_ip) alongside MACs
        src_str = f"{src} ({src_vendor})"
        if src_ip: src_str += f" / {src_ip}"

        dst_str = f"{dst} ({dst_vendor})"
        if dst_ip: dst_str += f" / {dst_ip}"

        print(f"{src_str} → {dst_str} | TCP {sport}->{dport}")
        print(f"→ {summary_str}")

        if payload:
            print("-"*80)
            try:
                print(hexdump(payload, dump=True))
            except Exception as e:
                print(f"[!] hexdump error: {e}")
        print("="*80)

    #---Flag TKIP--------------------------------
    elif pkt.haslayer(Dot11TKIP):
        found_any = True # Mark as found

        # --- Use our Timestamp De-duplicator ---
        now = datetime.now()
        flow_key = f"TKIP|{src}|{dst}"

        flow_data = _session_flows.get(flow_key)
        show_packet = False

        if not flow_data:
            flow_data = {
                'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now,
                'intel': "WPA/TKIP Encryption Detected (INSECURE)" # Store the intel
            }
            _session_flows[flow_key] = flow_data
            show_packet = True
        else:
            flow_data['count'] += 1
            flow_data['last_seen'] = now
            if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                show_packet = True
                flow_data['last_printed'] = now
            else:
                show_packet = False

        if show_packet:
            # --- START OF YOUR REQUESTED FIXES ---

            #pkt.show()

            # REQ 2: Get TID
            tid = "N/A"
            if pkt.haslayer(Dot11QoS):
                tid = pkt[Dot11QoS].TID

            # REQ 1: Get Length
            pkt_len = len(pkt)

            # REQ 3: Get Payload for Hexdump
            # The payload of the Dot11 frame *is* the TKIP layer
            payload = bytes(pkt[Dot11].payload)

            print("="*80)
            count = flow_data['count']
            first_seen_str = flow_data['first_seen'].strftime("%H:%M:%S")
            last_seen_str = flow_data['last_seen'].strftime("%H:%M:%S")

            header_str = f"[Seen: {count}x] [First: {first_seen_str}] [Last: {last_seen_str}] "

            # REQ 1 & 2: Modified Header Print
            print(f"{header_str}Type:{frame_type} Subtype:0x{subtype:02x} | Dir:{direction} | CH:{ch} | Len:{pkt_len} | TID:{tid}")

            print(f"{src} ({src_vendor}) → {dst} ({dst_vendor})")
            print("→ [!] INSECURE WPA/TKIP ENCRYPTION DETECTED")

            # REQ 3: Add Hexdump
            if payload:
                print("-"*80)
                try:
                    # This hexdump will include the TKIP header (TSC, WEPSeed, etc.)
                    print(hexdump(payload, dump=True))
                except Exception as e:
                    print(f"[!] hexdump error: {e}")

            print("="*80)

    # --- BLOCK x: HANDLE EAPOL HANDSHAKES ---
    elif pkt.haslayer(EAPOL):
        if pkt[EAPOL].type == 3: # Key frame only
            found_any = True

            # --- "JUST-IN-TIME" PCAP WRITING ---
            save_status = " [PCAP: Saved]"
            try:
                from scapy.all import wrpcap

                # 1. Check if we have a Beacon for this network that hasn't been saved yet
                if bssid and bssid in _beacon_cache and bssid not in _written_bssids:
                    # Write the Beacon FIRST so Aircrack knows the SSID
                    wrpcap(HANDSHAKE_PCAP, _beacon_cache[bssid], append=True)
                    _written_bssids.add(bssid) # Mark as saved
                    save_status = " [PCAP: Beacon+Handshake Saved]"

                # 2. Write the EAPOL packet
                wrpcap(HANDSHAKE_PCAP, pkt, append=True)

            except Exception as e:
                save_status = f" [Save Error: {e}]"
            # -----------------------------------

            # Track BSSIDs seen in EAPOL frames whose beacon wasn't cached yet,
            # so a later-arriving beacon can still be written (once) at that time.
            if bssid and bssid not in _beacon_cache:
                _pending_beacon_bssids.add(bssid)

            flow_key = f"EAPOL|{src}"
            now = datetime.now()

            # Classify from EAPOL-Key fields (M1..M4 / unclassified + retransmission)
            label, is_retx = classify_eapol_key(pkt[EAPOL], src)

            flow_data = _session_flows.get(flow_key)
            show_packet = False

            if not flow_data:
                flow_data = {
                    'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now,
                    'intel': "WPA2/3 4-Way Handshake Packet"
                }
                _session_flows[flow_key] = flow_data
                show_packet = True
            else:
                flow_data['count'] += 1
                flow_data['last_seen'] = now
                if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                    show_packet = True
                    flow_data['last_printed'] = now
                else:
                    show_packet = False

            # Handshake-visibility rule: message-number transitions are always
            # shown (each M1..M4 is a distinct event), and the first RETX of a
            # given message is shown; only exact repeats of an already-printed
            # (src, msg, replay_counter) beyond the first retransmission and
            # without cooldown expiry are suppressed.
            if not is_retx:
                # A new (different) message number in this flow always prints
                msg_sig = (src, label)
                if flow_data.get('last_msg_sig') != msg_sig:
                    flow_data['last_msg_sig'] = msg_sig
                    show_packet = True
                    flow_data['last_printed'] = now
            else:
                # Retransmission: print the first retransmission of a message,
                # suppress further identical ones until cooldown expires.
                retx_sig = (src, label, getattr(pkt[EAPOL], "key_replay_counter", None))
                if flow_data.get('last_retx_sig') != retx_sig:
                    flow_data['last_retx_sig'] = retx_sig
                    show_packet = True
                    flow_data['last_printed'] = now

            if show_packet:
                tid = "N/A"
                if pkt.haslayer(Dot11QoS):
                    tid = pkt[Dot11QoS].TID
                pkt_len = len(pkt)

                print("="*80)
                count = flow_data['count']
                t1 = flow_data['first_seen'].strftime("%H:%M:%S")
                t2 = flow_data['last_seen'].strftime("%H:%M:%S")

                header_str = f"[Seen: {count}x] [First: {t1}] [Last: {t2}] "
                retx_tag = " [RETX]" if is_retx else ""
                print(f"{header_str}Type:{frame_type} Subtype:0x{subtype:02x} | Dir:{direction} | CH:{ch} | Len:{pkt_len} | TID:{tid}")

                print(f"{src} ({src_vendor}) → {dst} ({dst_vendor})")
                print(f"→ EAPOL-Key {label}{retx_tag}: WPA2/3 Handshake{save_status}")
                print("="*80)

    # --- BLOCK 4: HANDLE ICMPv6 (Neighbor Discovery) ---
    elif pkt.haslayer(ICMPv6ND_NS):
        found_any = True
        icmpv6 = pkt[ICMPv6ND_NS]
        try:
            # Extract IPv6 addresses
            src_ip = pkt['IPv6'].src
            tgt_ip = icmpv6.tgt

            # 1. Generate the Intel String IMMEDIATELY
            # We need this for the Final Report, even if we don't print it now.
            summary_str = f"ICMPv6 Neighbor Solicitation: Who has {tgt_ip}? Tell {src_ip}"

            # 2. De-duplicate & Store Data
            now = datetime.now()
            flow_key = f"ICMPv6_NS|{src_ip}|{tgt_ip}"

            flow_data = _session_flows.get(flow_key)
            show_packet = False

            if not flow_data:
                 flow_data = {
                    'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now,
                    'intel': summary_str # Save it immediately!
                 }
                 _session_flows[flow_key] = flow_data
                 show_packet = True
            else:
                 flow_data['count'] += 1
                 flow_data['last_seen'] = now
                 flow_data['intel'] = summary_str # Always update it

                 if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                     show_packet = True
                     flow_data['last_printed'] = now
                 else:
                     show_packet = False

            # 3. FILTER OUT ROUTER NOISE
            # We don't want to see Routers (AP->STA) doing roll-call in the live view.
            if direction == "AP→STA":
                show_packet = False

            # 4. Print to Console (Only if allowed)
            if show_packet:
                 print("="*80)
                 count = flow_data['count']
                 first_seen_str = flow_data['first_seen'].strftime("%H:%M:%S")
                 last_seen_str = flow_data['last_seen'].strftime("%H:%M:%S")
                 print(f"[Seen: {count}x] [First: {first_seen_str}] [Last: {last_seen_str}] Type:IPv6 Subtype:ND | Dir:{direction} | CH:{ch}")

                 # Extract IP for header print if available (reusing logic from top)
                 src_str = f"{src} ({src_vendor})"
                 # Note: We don't need to re-check for IP here, we know it's IPv6
                 if src_ip: src_str += f" / {src_ip}"

                 print(f"{src_str} → {dst} ({dst_vendor})")
                 print(f"→ {summary_str}")
                 print("="*80)
        except Exception:
            pass

    # --- BLOCK 5: CATCH-ALL FOR ENCRYPTED/UNKNOWN DATA ---
    if not found_any:
        now = datetime.now()

        # 1. EXTRACT PAYLOAD
        if pkt.haslayer(Dot11):
             payload = bytes(pkt[Dot11].payload)
        else:
             payload = bytes(pkt)

        # 2. ANALYZE PAYLOAD
        is_cleartext = False
        text_preview = ""
        intel_str = "Encrypted Data" # Default
        flow_key = f"ENCRYPTED_DATA|{src}|{dst}" # Default

        matches = re.findall(rb"[ -~]{4,}", payload)
        if matches:
            total_text_len = sum(len(m) for m in matches)
            if total_text_len > 10:
                is_cleartext = True
                decoded_strings = [m.decode('utf-8', 'ignore') for m in matches]
                text_preview = " | ".join(decoded_strings)

                flow_key = f"UNKNOWN_TEXT|{src}|{dst}"
                intel_str = f"Cleartext: {text_preview}"

        # 3. DE-DUPLICATION
        flow_data = _session_flows.get(flow_key)
        show_packet = False

        if not flow_data:
            flow_data = {
                'count': 1, 'first_seen': now, 'last_seen': now, 'last_printed': now,
                'intel': intel_str
            }
            _session_flows[flow_key] = flow_data
            show_packet = True
        else:
            flow_data['count'] += 1
            flow_data['last_seen'] = now
            flow_data['intel'] = intel_str

            if now - flow_data['last_printed'] > PRINT_COOLDOWN:
                show_packet = True
                flow_data['last_printed'] = now
            else:
                show_packet = False

        # 4. PRINTING
        if show_packet:
            tid = "N/A"
            if pkt.haslayer(Dot11QoS):
                tid = pkt[Dot11QoS].TID
            pkt_len = len(pkt)

            print("="*80)
            count = flow_data['count']
            first_seen_str = flow_data['first_seen'].strftime("%H:%M:%S")
            last_seen_str = flow_data['last_seen'].strftime("%H:%M:%S")

            header_str = f"[Seen: {count}x] [First: {first_seen_str}] [Last: {last_seen_str}] "
            print(f"{header_str}Type:{frame_type} Subtype:0x{subtype:02x} | Dir:{direction} | CH:{ch} | Len:{pkt_len} | TID:{tid}")

            print(f"{src} ({src_vendor}) → {dst} ({dst_vendor})")

            if is_cleartext:
                print(f"→ Unknown Payload (Cleartext):")
                # --- THIS IS THE FIX ---
                # Wrap text to 75 chars so it doesn't break the terminal
                # but print ALL of it across multiple lines.
                wrapped_lines = textwrap.wrap(text_preview, width=75)
                for line in wrapped_lines:
                    print(f"    {line}")
                # -----------------------
            else:
                print("→ Encrypted 802.11 Data Frame (WPA2/3)")

            if payload:
                print("-"*80)
                try:
                    print(hexdump(payload, dump=True))
                except Exception:
                    pass
            print("="*80)

# -----------------------
# Main
# -----------------------
def main():
    if os.geteuid() != 0:
        print("[!] Run as root.")
        sys.exit(1)
            
    # --- Register our new Ctrl+C handler ---
    signal.signal(signal.SIGINT, signal_handler)

    load_manuf_db()
    load_seen_hashes()

    print(f"[*] Starting sniffer on {IFACE}. "
          f"Hopping channels {CHANNELS} every {HOP_INTERVAL}s (Ctrl+C to stop)")

    i = 0
    
    try:
        # --- Loop until our Ctrl+C flag is set ---
        while not _stop_sniffing.is_set():
            ch = CHANNELS[i % len(CHANNELS)]
            print(f"[+] Hopper: setting channel {ch}")

            if not set_channel(ch):
                if _stop_sniffing.is_set():
                    break # Stop immediately if channel set failed during shutdown
                i += 1
                continue # Skip sniffing if channel set failed

            # --- This is the sequential sniff ---
            # It runs in the *main thread*, blocks for HOP_INTERVAL seconds,
            # and checks our stop flag on every packet it receives.
            sniff(iface=IFACE, 
                  prn=packet_handler, 
                  store=False, 
                  timeout=HOP_INTERVAL,
                  stop_filter=lambda p: _stop_sniffing.is_set())

            i += 1

            time.sleep(0.1)

    except Exception as e:
        # Only print the error if we didn't intentionally stop
        if not _stop_sniffing.is_set():
            print(f"[!] Fatal error in main loop: {e}", file=sys.stderr)
            
    finally:
        save_seen_hashes()
        print("[*] Sniffer stopped.")

if __name__ == "__main__":
    main()

