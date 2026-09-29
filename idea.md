Build a simple CLI troubleshooting script (Python 3, single file, prefer standard
library; runs on Windows/Linux/macOS) that diagnoses internet problems in our office
network and helps fix them.

NETWORK CONTEXT
- ISP router: Cisco 4321 (ISP-owned). Gateway/LAN IP: 192.168.1.1
- ISP DNS: 58.71.2.8, 45.63.30.117
- Topology: ISP router -> D-Link switch 1 (port 23). Switches 2-5 cascade off switch 1
  on ports 24, 25, 26, 27 respectively.
- Switches are all D-Link DGS-1210-28 (Web Smart: 24 GbE + 4 SFP; CLI over Telnet
  only, compact CLI; SNMP v1/v2c/v3 supported).
- Switch management IPs: dlink1 10.90.90.90, dlink2 .91, dlink3 .92, dlink4 .93,
  dlink5 .94
- I only have access to the switches, not the router.

CHECKS (in order; stop and report at the first failing layer)
1. Local config: this PC's IP, subnet, gateway, DNS. Flag APIPA (169.254.x.x) or a
   gateway that isn't 192.168.1.1.
2. Gateway: ping 192.168.1.1 (loss %, avg latency, jitter).
3. Internet by IP: ping 1.1.1.1 and 8.8.8.8.
4. DNS: resolve a test domain against each ISP DNS and against 1.1.1.1/8.8.8.8 (use
   nslookup or a raw UDP query; report success and response time for each). ISP DNS
   failing while public DNS works = "ISP DNS problem".
5. Switches: ping all 5 management IPs; report which are unreachable and what that
   implies (uplink port or cascade problem).
6. Rogue DHCP: broadcast a DHCP discover with scapy (multi-answer collection, ~5 s
   wait) and list every responder with IP, Ethernet source MAC and vendor (OUI). Flag
   any responder other than the gateway. Fallback if scapy or admin rights are
   unavailable: nmap broadcast-dhcp-discover, then ARP the offered server IP for its
   MAC.
7. Trace to port: for each suspicious MAC, find its switch and port, starting at
   dlink1:
   - Method A (preferred): SNMP v2c read-only walk of the bridge FDB (Q-BRIDGE-MIB
     dot1qTpFdbPort, falling back to BRIDGE-MIB dot1dTpFdbPort), mapped to physical
     ports via dot1dBasePortIfIndex. Verify at startup that the FDB walk returns data
     on this firmware; if not, use Method B.
   - Method B (fallback): Telnet to the switch, log in, run "debug info" (dumps ARP
     table + MAC FDB on DGS-1210), and parse the output for the MAC. Use a small
     socket-based Telnet helper (telnetlib is removed in Python 3.13). Confirm the
     exact output format against a real switch before parsing.
   - Hop logic: if the MAC is on dlink1 port 24-27, query the matching downstream
     switch (24->dlink2, 25->dlink3, 26->dlink4, 27->dlink5) and repeat until it lands
     on an edge port. Report "Switch X, port Y". If found on port 23 of dlink1, report
     it as the ISP/upstream side.
   - Also run this trace for any duplicate IP/MAC conflicts found.
8. Loop/broadcast storm hints: gateway latency spikes or loss, a MAC learned on
   multiple ports or flapping, and (via SNMP) error/broadcast counters on ports 23-27
   of dlink1. Corroborate with the loopback-detection live loop status and the storm
   control counters from check 9.
9. Switch hardening audit (SNMP read-only; never changes switch config): for each of
   the 5 switches read the current state and report PASS/WARN/FAIL against the Switch
   Hardening Baseline below. A port reporting loop-detection loop state is direct
   evidence of a loop on that switch.
   - Loopback Detection: sysLBDStateEnable (global), sysLBDMode, sysLBDInterval,
     sysLBDRecoverTime, sysLBDPortStatus (per port), sysLBDPortLoopStatus (per port;
     "disabled" here means a loop was detected on that port).
   - Storm Control: broadcastStormCtrlGlobalOnOff, broadcastStormCtrlLimitType,
     broadcastStormCtrlThreshold.
   - RSTP: rstpStatus, STP version, bridge priority, root bridge.
   - Safeguard Engine: sysSafeGuardEnable (default enabled -> WARN if off).
   - DHCP Server Screening: dhcpServerScreenEnablePortlist + trusted-server table.
   - DoS Prevention: doSCtrlState.
   The DGS-1210 Telnet CLI cannot configure these features (it only exposes IP,
   password, save, reboot, reset config and "debug info"), so the audit is SNMP-only
   and all remediation is manual in the web UI.

OUTPUT
- One PASS/WARN/FAIL line per check, then "Likely cause" and "Suggested fix". For a
  rogue device, show the traced switch and port and tell me to unplug it. Also
  report the Switch Hardening Baseline (check 9) and, for anything below baseline,
  give the exact value to set in the web UI (L2 Functions > Loopback Detection,
  L2 Functions > Spanning Tree, Security > Storm Control, Security > DHCP Server
  Screening).
- Flags: --quick (checks 1-4 only), --log (save a timestamped report). Switch
  credentials and SNMP community come from environment variables or a config file
  (never hardcoded; default login is admin/admin, so warn if it is still in use).

SWITCH HARDENING BASELINE (recommended; applied manually in the web UI -- SNMP here
is read-only, and the DGS-1210 Telnet CLI cannot set these features)
- Loopback Detection: global enabled; port-based mode; interval 2 s; recover time 0
  (the port stays down until fixed -- 60 would flap back into the loop each minute);
  enabled per port on access ports only (dlink1 1-22 and the access ports of
  dlink2-5), off on the uplink (23) and the inter-switch ports (24-27).
- Storm Control: global enabled; type = Multicast & Broadcast & Unknown Unicast
  (fallback Multicast & Broadcast); threshold ~20000 Kbit/s on access ports; uplink
  and inter-switch ports disabled or a high backstop (~500000 Kbit/s) so legit
  traffic is never dropped.
- RSTP: global enabled; version RSTP; bridge priority dlink1 = 4096 (force it root,
  otherwise the switch with the lowest MAC wins and a downstream switch can become
  root), dlink2-5 = 32768; access ports Edge=True, P2P=Auto, Restricted Role=True,
  Restricted TCN=True; uplink/inter-switch ports Edge=False, P2P=True, Migrate=Yes.
- Safeguard Engine: enabled (default).
- DHCP Server Screening: enabled on access ports; trusted server 192.168.1.1; do NOT
  screen port 23 or the inter-switch ports, or DHCP replies from the ISP router get
  dropped.
- DoS Prevention: enabled (optional). ARP Spoofing Prevention: optional rule
  192.168.1.1 -> router MAC. Port Security: not recommended (breaks normal device
  moves in an office).
- Why: Loopback Detection catches edge loops STP cannot see (both ends of a cable
  into two wall ports, or a looped unmanaged switch/hub) and shuts the port; Storm
  Control caps the blast radius of a storm; RSTP is a safety net for loops between
  managed switches and fast link-failure recovery. This topology is a strict tree
  (router -> dlink1 -> dlink2-5), so RSTP is mostly dormant here -- Loopback
  Detection and Storm Control are the features that matter.

OPTIONAL FIXES (each behind a y/N prompt)
- Flush the DNS cache; renew the DHCP lease; set this PC's DNS to 1.1.1.1/8.8.8.8.

CONSTRAINT
- Never access or configure the ISP router.
- The script reads switch state only (SNMP); it never writes switch configuration.

Start by proposing the file structure and check flow in a few lines, then write the
script, then give a short usage guide.
