# Port Scanning with OS Information/Version  

## What is Port Scanning?  

**TCP/IP (Transmission Control Protocol/Internet Protocol)** is the internet protocol suite which is the conceptual model and set of communication protocols used in the Internet and similar computer networks. In TCP/IP model, there is a notion of **IP Address** which is a **Layer-3/Network-layer Address** and used to reference **Server/Host Machines** in networks. In addition to IP address, there is also a notion of **Port** which is a **Layer-4/Transport-layer Address** and used to connect and get services  from specific application running on a server/host machine in the network.  

**Port scanning** is a systematic approach to probe a server/host machine for **Open Ports**. It, itself, is not a **Network-level Threat**. Network administrators may do port scanning to verify security policy of the network for improving overall security posture of the organizational network. But, attackers may also do port scanning to identify network services running on a server/host machine and exploit their **Vulnerabilities**. The attackers use port scanning as a vehicle for carrying out **Reconnaissance Attack**, that is, they try to get information about a particular network so that they can identify how the  network may behave if **Malicious Connections** are made. If they can find an open port corresponding to a specific service and the vulnerability of that service is known, then they can attack that service via open port.  


## Ports on a Server/Host Machine  

Usually, 16 bits are used to encode and identify **Port Number** on a server/host machine. Therefore, there are  2<sup>16</sup> = 65,536 possible ports. But, `port 0` is left unassigned and used by **Operating System** to accept request for allocating and opening any currently unused port. Hence, there are, in total, 2<sup>16</sup>-1 = 65,535 ports on a server/host machine.  

Most **Internet applications** run on **Well-defined Ports**. Example of associations between Internet applications and server/host machine ports is given below:  
| Port Number 	| Internet Application Running         	|
|-------------	|--------------------------------------	|
| `port 21`   	| FTP (File Transfer Protocol)         	|
| `port 22`   	| SSH (Secure Shell Protocol)          	|
| `port 23`   	| Telnet Protocol                      	|
| `port 25`   	| SMTP (Simple Mail Transfer Protocol) 	|
| `port 53`   	| DNS (Domain Name System)             	|
| `port 80`   	| HTTP (Hypertext Transfer Protocol)   	|
| `port 443`  	| HTTPS (HTTP Secure)                  	|
| `port 1433` 	| SQL Server                           	|  

Normally, all ports on a server/host machine are not scanned during port scanning. Instead, ports with known applications running or known exploitable vulnerabilities are cherry-picked and scanned.  

Typically, port scanning works by trying to **Systematically** establish connections to all available ports on a given server/host machine. When such an attempt to establish connections is made, one may get one of the three different types of **Responses** from the corresponding port on server/host machine. These responses are:  
1) `open/accepted`: service in question is **Listening for New Connections** on specified port  
2) `closed/denied`: service in question is **Not Listening for New Connections** on specified port  
3) `filtered/dropped/blocked`: **No Reply** from specified port running service in question  

![responses](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/responses.jpeg?raw=true)


## Implementation  

There are many techniques that are typically used to implement port scanning.  

### TCP `connect()` (Full-open) Port Scanning  

![full-open-port-scanning](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/full-open-port-scanning.jpeg?raw=true)

### TCP `SYN` (Half-open) Port Scanning  

![half-open-port-scanning](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/half-open-port-scanning.jpeg?raw=true)

### TCP `connect()` Port Scanning vs TCP `SYN` Port Scanning  



### Other Port Scanning Implementation Techniques  

#### TCP `FIN` Port Scanning  

Often, **Firewall** and **Packet Filters** monitor specified ports so that the previously mentioned techniques of TCP port scanning  can be detected. To bypass this detection, **TCP Packet with FIN Flag** may be used. Usually, this packet is used to finish an established connection with server/host machine. If TCP FIN packet is sent before establishing a connection, an open port discards the packet and a closed port replies with a **TCP Packet with RST Flag**. So, open and closed ports can be distinguished between by looking at the TCP RST reply from the target port on server/host machine. Though some systems, regardless of whether the port is open, reply to TCP FIN packet with TCP RST packet to prevent this type of scanning method, TCP FIN port scanning may come in handy for many systems.  

#### UDP Raw ICMP Port Unreachable Scanning  

This port scanning implementation technique differs from the aforementioned techniques in that it uses **UDP (User Datagram Protocol)** instead of TCP. While this protocol is simpler compared to TCP, scanning with this protocol is significantly more difficult. This is because open ports are not obliged to send an acknowledgement in response to the scanning probe and close ports are not even required to send an error packet. Fortunately, most server/host machines do send an `ICMP_PORT_UNREACH` error when a packet is sent to a closed UDP port. Thus, open and closed ports can be distinguished between by looking at the receipt of `ICMP_PORT_UNREACH` error. Again, neither UDP packet nor **ICMP (Internet Control Message Protocol) Error** are guaranteed to arrive. So, UDP port scanner of this type must also implement **Packet Retransmission Mechanism**. This port scanning implementation technique is very slow. Again, this technique requires the attacker to have **Root Privileges**.  

#### UDP `recvfrom()` and `write()` Port Scanning  

An attacker without root privileges can not read `ICMP_PORT_UNREACH` error directly. But, **Linux** can indirectly notify the attacker when the error arrives. This port scanning implementation technique is used to check whether the port is open.  

The reason behind so many implementation techniques for port scanning being developed by attackers is that any of these techniques may potentially get detected by network security systems like **IDS (Intrusion Detection System)**, **Firewall**, etc. Therefore, many implementation techniques for port scanning have been developed over the time so that an attacker can successfully bypass the detection and carry out the desired attack on server/host machine. Each of these implementation techniques has its own subtle method along with pros and cons.  

