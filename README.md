# Simple-NIDS
# Advanced Network IDS Analyzer

## Project Overview

Advanced Network IDS Analyzer is a Python-based Intrusion Detection System (IDS) designed to analyze captured network traffic stored in PCAP and PCAPNG files. The application provides a graphical user interface (GUI) that enables users to inspect network activity, collect protocol statistics, detect suspicious patterns, and visualize results through charts.

The project was developed for educational and research purposes to demonstrate fundamental IDS concepts and network traffic analysis techniques.

---

## Features

* PCAP and PCAPNG file analysis
* Detection of common network attack patterns
* Protocol traffic statistics collection
* Graphical visualization of network data
* Configurable detection thresholds
* Automatic attack logging
* Multi-threaded packet processing
* User-friendly graphical interface

---

## Technologies Used

### Programming Language

* Python 3.x

### Libraries

* Tkinter (GUI development)
* Scapy (Packet analysis)
* Matplotlib (Data visualization)
* Threading (Concurrent processing)

---

## Detection Capabilities

The IDS analyzes network traffic and attempts to identify the following suspicious activities:

### SYN Flood Detection

Monitors excessive TCP SYN packets that may indicate a SYN Flood denial-of-service attack.

### HTTP Flood Detection

Tracks large amounts of HTTP traffic that may represent an application-layer flooding attack.

### DNS Flood Detection

Identifies abnormal DNS request volumes.

### UDP Flood Detection

Detects excessive UDP traffic commonly associated with denial-of-service attacks.

### ICMP Flood Detection

Monitors high volumes of ICMP packets that may indicate a Ping Flood attack.

### ARP Scan Detection

Detects abnormal ARP traffic patterns that may suggest network reconnaissance activities.

### TCP Anomaly Detection

Identifies unusually high TCP traffic volumes.

### Slowloris Detection

Attempts to identify traffic characteristics associated with Slowloris attacks.

---

## System Workflow

1. The user selects a PCAP or PCAPNG file.
2. Network packets are loaded using Scapy.
3. Protocol statistics are collected.
4. Detection thresholds are applied.
5. Potential attacks are identified.
6. Results are displayed in the graphical interface.
7. A bar chart is generated for traffic visualization.
8. Detected events are stored in a log file.

---

## Output

The application generates:

* Protocol statistics
* Attack detection reports
* Visual traffic charts
* Attack log file (`attack_log.txt`)

---

## How to Run

### Install Required Packages

```bash
pip install scapy matplotlib
```

### Run the Program

```bash
python ids_analyzer.py
```

---

## Example Output

```text
===== PACKET STATISTICS =====
Total Packets: 5000
TCP: 3200
UDP: 900
ICMP: 300
HTTP: 1200
DNS: 400

===== ATTACK ANALYSIS =====
SYN FLOOD DETECTED (650)
HTTP FLOOD DETECTED (450)
```

---

## Limitations

* Signature-based threshold detection only
* No machine learning capabilities
* Designed for offline PCAP analysis
* Does not perform real-time packet monitoring
* Detection accuracy depends on threshold configuration

---

## Future Improvements

* Real-time packet capture support
* Machine learning-based anomaly detection
* Export reports in PDF format
* Advanced protocol analysis
* Database integration
* Web dashboard implementation

# Attack Detection Mechanisms

## SYN Flood Attack

A SYN Flood is a Denial-of-Service (DoS) attack that exploits the TCP three-way handshake process. During a normal TCP connection, a client sends a SYN packet, the server responds with a SYN-ACK packet, and the client completes the connection with an ACK packet.

In a SYN Flood attack, the attacker sends a large number of SYN packets but never completes the handshake. As a result, the server allocates resources for thousands of half-open connections, eventually exhausting available resources and preventing legitimate users from connecting.

### Indicators

* Excessive TCP SYN packets
* Large number of incomplete TCP connections
* Increased server resource consumption

---

## HTTP Flood Attack

An HTTP Flood is an application-layer Distributed Denial-of-Service (DDoS) attack. Instead of overwhelming a target with raw packets, the attacker sends a massive number of seemingly legitimate HTTP requests.

Because these requests often appear normal, they are more difficult to distinguish from legitimate traffic. The goal is to consume server CPU, memory, bandwidth, or application resources.

### Indicators

* Unusually high volume of HTTP requests
* Increased web server response times
* High CPU utilization on web servers

---

## DNS Flood Attack

A DNS Flood attack targets DNS infrastructure by generating a large number of DNS requests within a short period. The objective is to overwhelm DNS servers and prevent legitimate domain name resolution.

Attackers may use botnets to generate traffic from multiple sources, making mitigation more difficult.

### Indicators

* Excessive DNS query traffic
* Increased DNS response latency
* DNS service degradation or outage

---

## UDP Flood Attack

UDP Flood attacks involve sending a large number of UDP packets to random or specific ports on a target system. Since UDP is connectionless and requires no handshake, attackers can generate traffic at very high rates.

The target system may spend significant resources processing packets or generating ICMP destination-unreachable responses.

### Indicators

* Abnormally high UDP packet counts
* Network bandwidth saturation
* Increased CPU and memory utilization

---

## ICMP Flood Attack

An ICMP Flood, commonly known as a Ping Flood, overwhelms a target with ICMP Echo Request packets. The victim attempts to process and respond to each request, consuming network and system resources.

Large-scale ICMP Floods can lead to degraded performance or service disruption.

### Indicators

* Excessive ICMP Echo Requests
* High network utilization
* Reduced system responsiveness

---

## ARP Scan Attack

ARP Scanning is a reconnaissance technique used to discover active devices on a local network. An attacker sends ARP requests to multiple IP addresses and records the responses to identify reachable hosts.

Although ARP scanning is not always malicious, it is often a preliminary step before more advanced attacks.

### Indicators

* Large numbers of ARP requests
* Sequential scanning of IP ranges
* Rapid host discovery activity

---

## TCP Anomaly Detection

TCP Anomaly Detection identifies unusual TCP traffic behavior that differs significantly from expected network patterns. High TCP volumes may indicate scanning activity, denial-of-service attacks, malware communication, or other suspicious behavior.

### Indicators

* Unexpected spikes in TCP traffic
* Abnormal connection rates
* Unusual port communication patterns

---

## Slowloris Attack

Slowloris is a low-bandwidth application-layer denial-of-service attack. Instead of flooding a server with large amounts of traffic, the attacker opens many HTTP connections and keeps them alive for as long as possible by periodically sending partial requests.

The web server eventually exhausts its available connection pool and becomes unable to serve legitimate clients.

### Indicators

* Large numbers of long-lived HTTP connections
* Many incomplete HTTP requests
* Connection exhaustion on the target server

---

# Important Note About This Project

The current IDS implementation uses threshold-based detection. This means that attacks are identified when packet counts exceed predefined limits. While effective for demonstrating IDS concepts, this approach does not perform deep packet inspection, behavioral analysis, or machine learning-based threat detection.

As a result, detections should be considered indicators of suspicious activity rather than definitive proof of an attack.


