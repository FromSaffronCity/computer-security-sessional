# Port Scanning with OS Information/Version  



## What is Port Scanning?  

**TCP/IP (Transmission Control Protocol/Internet Protocol)** is the internet protocol suite which is the conceptual model and set of communication protocols used in the Internet and similar computer networks. In TCP/IP model, there is a notion of **IP Address** which is a **Layer-3/Network-layer Address** and used to reference **Server/Host Machines** in networks. In addition to IP address, there is also a notion of **Port** which is a **Layer-4/Transport-layer Address** and used to connect and get services  from specific application running on a server/host machine in the network.  

**Port scanning** is a systematic approach to probe a server/host machine for **Open Ports**. It, itself, is not a **Network-level Threat**. Network administrators may do port scanning to verify security policy of the network for improving overall security posture of the organizational network. But, attackers may also do port scanning to identify network services running on a server/host machine and exploit their **Vulnerabilities**. The attackers use port scanning as a vehicle for carrying out **Reconnaissance Attack**, that is, they try to get information about a particular network so that they can identify how the  network may behave if **Malicious Connections** are made. If they can find an open port corresponding to a specific service and the vulnerability of that service is known, then they can attack that service via open port.  




## Ports on a Server/Host Machine  

Usually, 16 bits are used to encode and identify **Port Number** on a server/host machine. Therefore, there are  2<sup>16</sup> = 65,536 possible ports. But, `port 0` is left unassigned and used by **Operating System** to accept request for allocating and opening any currently unused port. Hence, there are, in total, 2<sup>16</sup>-1 = 65,535 ports on a server/host machine.  

Most **Internet applications** run on **Well-defined Ports**. Example of associations between Internet applications and server/host machine ports is given below:  

| Port Number | Internet Application Running         |
| ----------- | :----------------------------------- |
| `port 21`   | FTP (File Transfer Protocol)         |
| `port 22`   | SSH (Secure Shell Protocol)          |
| `port 23`   | Telnet Protocol                      |
| `port 25`   | SMTP (Simple Mail Transfer Protocol) |
| `port 53`   | DNS (Domain Name System)             |
| `port 80`   | HTTP (Hypertext Transfer Protocol)   |
| `port 443`  | HTTPS (HTTP Secure)                  |
| `port 1433` | SQL Server                           |

Normally, all ports on a server/host machine are not scanned during port scanning. Instead, ports with known applications running or known exploitable vulnerabilities are cherry-picked and scanned.  

Typically, port scanning works by trying to **Systematically** establish connections to all available ports on a given server/host machine. When such an attempt to establish connections is made, one may get one of the three different types of **Responses** from the corresponding port on server/host machine. These responses are:  
1. `open/accepted`: service in question is **Listening for New Connections** on specified port  
2. `closed/denied`: service in question is **Not Listening for New Connections** on specified port  
3. `filtered/dropped/blocked`: **No Reply** from specified port running service in question  

![responses](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/responses.jpeg?raw=true)


## Implementation  

There are many techniques that are typically used to implement port scanning. These techniques are discussed in the following subsections.  



### TCP `connect()` (Full-open) Port Scanning  

![full-open-port-scanning](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/full-open-port-scanning.jpeg?raw=true)

This is the most common and simplest technique used in port scanning implementation. **TCP** `connect()` is a **System Command** used to establish connection with server/host machine through a port. The connection is established via a **Three-way Handshaking** scheme as depicted in the above diagram.  



### TCP `SYN` (Half-open) Port Scanning  

![half-open-port-scanning](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/half-open-port-scanning.jpeg?raw=true)

**TCP** `SYN` port scanning works in a similar fashion to **TCP** `connect()` port scanning. The difference is that after receiving `SYN+ACK` from server/host machine, the attacker responds with **TCP** `RST` instead of **TCP** `ACK` to terminate the connection.  



### TCP `connect()` Port Scanning vs TCP `SYN` Port Scanning  

The problems with TCP `connect()` port scanning are discussed below:  
- During TCP three-way handshaking, server/host machine allocates some space in its memory to store details on the connection at targeted port and state of the three-way handshaking. If attacker stops responding and does not complete TCP three-way handshaking, then server/host machine will not release previously allocated memory for that connection. Eventually, server/host machine may run out of memory and stop working.  
- From attacker's perspective, an attempt to scan a port on server/host machine should go unnoticed. **IPS (Intrusion Prevention System)** looks for number of ports on server/host machine with fully established connection (connection established via three-way handshaking) and decides on whether the machine is a victim of port scanning attack. Hence, completing three-way handshake risks the port scanning detection.  
- As soon as the three-way handshake is completed, the application running on the targeted port takes control of the established connection. Consequently, the application as well as the entire server/host machine may crash if attacker tries to abruptly terminate the connection.  

Therefore, an attacker may not prefer TCP `connect()` port scanning. TCP `SYN` port scanning tackles the issue with TCP `connect()` port scanning.  



### Other Port Scanning Implementation Techniques  



#### TCP `FIN` Port Scanning  

Often, **Firewall** and **Packet Filters** monitor specified ports so that the previously mentioned techniques of TCP port scanning  can be detected. To bypass this detection, **TCP Packet with FIN Flag** may be used. Usually, this packet is used to finish an established connection with server/host machine. If TCP FIN packet is sent before establishing a connection, an open port discards the packet and a closed port replies with a **TCP Packet with RST Flag**. So, open and closed ports can be distinguished between by looking at the TCP RST reply from the target port on server/host machine. Though some systems, regardless of whether the port is open, reply to TCP FIN packet with TCP RST packet to prevent this type of scanning method, TCP FIN port scanning may come in handy for many systems.  



#### UDP Raw ICMP Port Unreachable Scanning  

This port scanning implementation technique differs from the aforementioned techniques in that it uses **UDP (User Datagram Protocol)** instead of TCP. While this protocol is simpler compared to TCP, scanning with this protocol is significantly more difficult. This is because open ports are not obliged to send an acknowledgement in response to the scanning probe and close ports are not even required to send an error packet. Fortunately, most server/host machines do send an `ICMP_PORT_UNREACH` error when a packet is sent to a closed UDP port. Thus, open and closed ports can be distinguished between by looking at the receipt of `ICMP_PORT_UNREACH` error. Again, neither UDP packet nor **ICMP (Internet Control Message Protocol) Error** are guaranteed to arrive. So, UDP port scanner of this type must also implement **Packet Retransmission Mechanism**. This port scanning implementation technique is very slow. Again, this technique requires the attacker to have **Root Privileges**.  



#### UDP `recvfrom()` and `write()` Port Scanning  

An attacker without root privileges can not read `ICMP_PORT_UNREACH` error directly. But, **Linux** can indirectly notify the attacker when the error arrives. This port scanning implementation technique is used to check whether the port is open.  

The reason behind so many implementation techniques for port scanning being developed by attackers is that any of these techniques may potentially get detected by network security systems like **IDS (Intrusion Detection System)**, **Firewall**, etc. Therefore, many implementation techniques for port scanning have been developed over the time so that an attacker can successfully bypass the detection and carry out the desired attack on server/host machine. Each of these implementation techniques has its own subtle method along with pros and cons.  




## OS Detection  

Sometimes on a network it is beneficial to know the Operating System (OS) of a machine. Accessing a system is easier when you know the OS because you can specifically search the Internet for known security holes in the OS. Granted, security holes are usually patched quickly, but you need to know when a security hole exists.  



### OS Detection Database  

Each Operating System (OS) has unique characteristics in its TCP/IP stack implementation that may serve to identify it on a network. There is a wide range of techniques and methods that helped us get a good estimate of the operating system running on a certain remote machine.

One approach is to use active fingerprinting. That is, special “probe” packets are sent to a certain machine, and based on its response, a certain OS is assumed.

Another approach is to use passive fingerprinting (as used in our project), where legitimate traffic is analyzed and compared for certain key differences in the TCP/IP stack implementation on different versions and types of operating systems.

NMAP has a database which is installed when you install NMAP. The database is used when doing OS detection through os fingerprinting (https://www.google.com/search?q=what+is+operating+system+fingerprinting&rlz=1C1RLNS_enBD933BD933&oq=what+is+os+fingerpri&aqs=chrome.2.0j69i57j0i22i30l3j0i390.5419j0j15&sourceid=chrome&ie=UTF-8), but it is not automatically updated. To look on the Internet for an updated version go to [https://svn.nmap.org/nmap/nmap-os-db](https://svn.nmap.org/nmap/nmap-os-db) as shown in Figure 1.  



### OS Detection Process  

Before we get into the actual command and performing an OS Detection we should cover some details about what is happening during this scan.  

There are five separate probes being performed. Each probe may consist of one or more packets. The response to each packet by the target system helps to determine the OS type.  

The five different probes are:  
1.  Sequence Generation
2.  ICMP Echo
3.  TCP Explicit Congestion Notification
4.  TCP
5.  UDP

Now we can look at these individually to see what they are doing.  

#### Sequence Generation  

The Sequence Generation Probe consists of six packets. The six packets are sent 100 ms apart and are all TCP SYN packets.  

The result of each TCP SYN packet will help NMAP determine the OS type.  

#### ICMP Echo  

Two ICMP Request packets are sent to the target system with varying settings in the packet.  

The resulting responses will help verify the OS type by NMAP.  

#### TCP Explicit Congestion Notification  

When a lot of packets are being generated and passing through a router causing it to be burdened is known as congestion. The result is that systems slow down to reduce congestion so the router is not dropping packets.  

The packet being sent is only to get a response from the target system. Specific values returned are used to determine the specific OS since each OS handles the packets in different ways.  

#### TCP  

Six packets are sent during this probe.  

Some packets are sent to open or closed ports with specific packet settings. Again, the results will vary depending on the target OS.  

The TCP Packets are all sent with varying flags as follows:  

1.  no flags
2.  SYN, FIN, URG and PSH
3.  ACK
4.  SYN
5.  ACK
6.  FIN, PSH, and URG  

![tcp-header](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/res/tcp-header.jpeg?raw=true)

#### UDP  

This probe consists of a single packet sent to a closed port.  

If the port used on the target system is closed and an ICMP Port Unreachable message is returned then there is no Firewall.  


## Justification  
