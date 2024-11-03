# SYN Flood Attack Detection Script

This Python script detects potential SYN flood attacks by monitoring TCP packets and identifying repeated SYN requests from individual IP addresses. When an IP exceeds a configured rate threshold, it is blocked using `iptables`, and the incident is logged.

## Requirements

- **Root Privileges**: This script requires root privileges to capture network packets and block IPs.
- **Dependencies**: 
  - Python 3
  - `socket`, `time`, `collections`, and `os` (standard libraries)

## How It Works

1. **Packet Capture**: The script listens to incoming IPv4 TCP packets using a raw socket.
2. **SYN Flag Detection**: For each packet, it checks if the SYN flag is set, indicating a connection initiation request.
3. **Rate Limiting**: It maintains a count of SYN requests from each IP address. If the average interval between SYN requests from an IP falls below a threshold (indicating possible flooding), that IP is blocked.
4. **IP Blocking**: The offending IP is blocked using `iptables`, and a log entry is recorded.

## Configuration

The following parameters can be adjusted within the script:
- `intervalo_tempo`: Interval (in seconds) to reset SYN counters.
- `threshold_ms`: Average interval threshold (in milliseconds) below which an IP is considered malicious.

## Usage

1. Clone or copy the script to a directory.
2. Run the script with root privileges:

    ```bash
    sudo python3 syn_flood_detector.py
    ```

3. **Logs**: IPs blocked due to potential SYN flood attacks are logged in `log_syn_flood.txt`.

## Functions

- `monitorar_pacotes()`: Captures packets, extracts IP and TCP flags, and processes SYN packets.
- `processar_pacote_syn(ip_origem)`: Manages SYN packet counts, checks if an IP exceeds the SYN threshold, and triggers blocking.
- `bloquear_ip(ip)`: Blocks the offending IP using `iptables`.
- `registrar_log(ip)`: Logs the blocked IP.
- `media_timestamps(list_timestamps)`: Calculates the average time interval between SYN requests from a given IP.

## Note

Ensure you have permission to modify `iptables` rules on your system, as this script will add IP blocking rules which may affect network behavior.

## Disclaimer

This script is for educational purposes and should be used responsibly on networks you own or are authorized to monitor. Unauthorized use on networks is prohibited.
