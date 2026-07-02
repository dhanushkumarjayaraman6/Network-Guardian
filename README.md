# Network Guardian — Legal Site Filtering & Violation Monitoring for Home WiFi

A home-network content filter that blocks illegal/unsafe sites (piracy, adult content,
malware, phishing) for every device on your WiFi, and flags devices that repeatedly
try to reach them — so you can act on it from your router's own admin panel.

## How it works

1. **Pi-hole** runs as a DNS server on your existing PC (via Docker — no Raspberry Pi
   or special router needed). It resolves DNS requests for every device on your network
   and blocks anything on the loaded blocklists (see `blocklists.txt`).
2. Your **router's DNS setting** is pointed at your PC's local IP, so every device on
   the WiFi (phones, laptops, smart TVs) automatically uses Pi-hole for DNS — this is a
   standard router setting change, not a hack.
3. **'monitor.py'** watches Pi-hole's query log in the background. If a device racks up
   repeated blocked-site attempts in a short window, it's flagged as a violator.
4. **'dashboard.py'** gives you a live Streamlit view of blocked domains, top offending
   devices, and flagged violators.

## Why this doesn't "auto cut the WiFi"

Automatically disconnecting a device from WiFi requires either ARP spoofing or
deauthentication packets — these are network-attack techniques, and using them (even on
your own network, and definitely on anyone else's) can violate wireless regulations and
is the same technique used in malicious WiFi attacks. Instead, this project's dashboard
tells you exactly which device to block, and you do it with your router's own built-in
**Parental Controls / Access Control / Device Manager** feature — a safe, one-click,
completely standard action that almost every modern router already supports (e.g. TP-Link
Tether, Netgear Nighthawk app, Asus Router app, D-Link, Xiaomi Router app all have this).

## Setup

### 1. Start Pi-hole
```bash
docker compose up -d
```
Open `http://<your-pc-ip>:8080/admin` and log in with the password set in
`docker-compose.yml` (`WEBPASSWORD`). **Change this password before first run.**

### 2. Load the blocklists
In the Pi-hole admin UI: **Group Management → Adlists** → paste in each URL from
`blocklists.txt` → **Save** → then **Tools → Update Gravity**.

### 3. Point your router at Pi-hole
Log into your router's admin page → find the **DNS settings** (usually under
"Internet" or "WAN/LAN setup") → set the **Primary DNS** to your PC's local IP
address (e.g. `192.168.1.50`) → save and reboot the router. All devices on the
network will now use Pi-hole for DNS automatically.

### 4. Run the monitor

pip install -r requirements.txt
python monitor.py

Leave this running in the background (or set it up as a scheduled/startup task).

### 5. Run the dashboard

streamlit run dashboard.py


### Project structure

 docker-compose.yml   # Pi-hole container config
 blocklists.txt       # Public blocklist sources (piracy/adult/malware)
 monitor.py           # Watches for repeated blocked-site attempts
 dashboard.py         # Streamlit dashboard
 requirements.txt
 README.md


### Notes:

'DB_PATH' in 'monitor.py' and 'dashboard.py' assumes the default Docker volume path;
  adjust if you change the volume mapping in 'docker-compose.yml'.
Threshold for flagging a device ('VIOLATION_THRESHOLD', 'VIOLATION_WINDOW_SECONDS'
  in 'monitor.py') is adjustable.
- This filters by **domain**, which covers the vast majority of piracy/adult/malware
  sites. It won't catch traffic over raw IPs or VPNs — no DNS-based filter can.
