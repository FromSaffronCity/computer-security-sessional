# Port Scanning with OS Information/Version  



## Quick Overview  



### What is Port Scanning?  

**Port Scanning** is a method for determining **Open Ports** in a computer network or on a remote server/host machine. It is usually done by sending connection request to remote server/host machine.  



### What is OS Fingerprinting?  

**OS Fingerprinting** is a method for estimating the **Operating System** running on a remote server/host machine. It is usually done by crafting special network packets and analyzing the responses **(Active)** or analyzing the trivial network traffic **(Passive)**.  



## Attack Description  

The following programs have been coded and scripts have been written to implement the attack tool:  

- `os_fingerprinting.py` is a Python script designed and written for carrying out OS fingerprinting.  
- `port_scanning.cpp` is a C++ program designed and coded for carrying out port scanning.  
- `run.sh` is a Linux shell script designed and written for compiling and running the overall attack tool.  



The attack sequence and the observed outputs after carrying out an attack are discussed and exhibited in the following subsections.  



### Attack Sequence  

The overall attack is carried out in several steps.  



### Observed Outputs  

It should be emphasized that while not explicitly illegal, **Port Scanning and OS Fingerprinting without Permission is Strictly Prohibited**. The owner of the victim server/host machine can sue the person responsible for the attacks. Therefore, all the attacks for testing and reporting purposes have been carried out targeting the following server/host machines:  

1. **TOTOLINK Router** with private IP address `192.168.1.1`  which is running on **Junos OS (Linux and FreeBSD)**  
2. **Laptop** with private IP address `192.168.1.11` which is running on **Windows 10 OS**  
3. **Virtual Machine** with private IP address `192.168.1.16` which is running on **Linux OS (Ubuntu 16.04)**  
4. `localhost` with IP address `127.0.0.1`  
5. `scanme.nmap.org` with IP address `45.33.32.156`  

[scanme.nmap.org](http://scanme.nmap.org/) is a service provided by [nmap.org](https://nmap.org/) and [insecure.org](https://insecure.org/). They set up a machine so that enthusiasts can learn about **Nmap (Network Mapper)** and test Nmap installation. The enthusiasts are authorized to carry out port scanning on this machine with Nmap or other port scanners. Not to mention, I own rest of the server/host machines mentioned above.  



Following ports have been scanned while carrying out port scanning:  

| Port Number | Internet Application Running         |
| ----------- | :----------------------------------- |
| `port 21`   | FTP (File Transfer Protocol)         |
| `port 22`   | SSH (Secure Shell Protocol)          |
| `port 23`   | Telnet Protocol                      |
| `port 24`   | Private Mail System                  |
| `port 25`   | SMTP (Simple Mail Transfer Protocol) |
| `port 80`   | HTTP (Hypertext Transfer Protocol)   |
| `port 443`  | HTTPS (HTTP Secure)                  |
| `port 8080` | Alternative to `port 80`             |



With a view to comparing the outputs side by side, all the attacks have been carried out using both the Nmap and the attack tool. The observed outputs from the attacker's perspective **(Virtual Machine with Private IP Address `192.168.1.16`)** are exhibited in the following subsections.  



#### Victim: `192.168.1.1`  

##### Nmap  

![192.168.1.1](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/nmap/192.168.1.1.png?raw=true)



##### Attack Tool  

![192.168.1.1](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/port.scanner/192.168.1.1.png?raw=true)



#### Victim: `192.168.1.11`  

##### Nmap  

![192.168.1.11](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/nmap/192.168.1.11.png?raw=true)



##### Attack Tool  

![192.168.1.11](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/port.scanner/192.168.1.11.NAT.png?raw=true)



#### Victim: `192.168.1.16`  

##### Nmap  

![192.168.1.16](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/nmap/192.168.1.16.png?raw=true)



##### Attack Tool  

![192.168.1.16](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/port.scanner/192.168.1.16.png?raw=true)



#### Victim: `localhost`  

##### Nmap  

![localhost](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/nmap/localhost.png?raw=true)



##### Attack Tool  

![localhost](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/port.scanner/localhost.png?raw=true)



#### Victim: `scanme.nmap.org`  

##### Nmap  

![scanme.nmap.org](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/nmap/scanme.nmap.org.png?raw=true)  



##### Attack Tool  

![scanme.nmap.org.NAT](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/res/port.scanner/scanme.nmap.org.NAT.png?raw=true)



## Attack Analysis  



## OS Fingerprinting with Available Tool  

In order to abide by the imposed constraints, OS fingerprinting tool available on the Github repository [OS-Fingerprinting](https://github.com/cesarghali/OS-Fingerprinting) (coded and written by [Cesar Ghali](https://github.com/cesarghali)) has been thoroughly studied and examined.  



## Countermeasures  

