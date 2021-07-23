# Port Scanning with OS Information/Version  



## Quick Overview  



### What is Port Scanning?  

**Port Scanning** is a method for determining **Open Ports** in a computer network or on a remote server/host machine. It is usually done by sending connection request to remote server/host machine.  



### What is OS Fingerprinting?  

**OS Fingerprinting** is a method for estimating the **Operating System** running on a remote server/host machine. It is usually done by crafting special network packets and analyzing the responses **(Active)** or analyzing the trivial network traffic **(Passive)**.  



## Attack Description  

The following programs have been coded and scripts have been written to implement the attack tool:  

- `os_fingerprinting.py` [(script)](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/src/os_fingerprinting.py) is a Python script designed and written for carrying out OS fingerprinting.  
- `port_scanning.cpp` [(code)](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/src/port_scanning.cpp) is a C++ program designed and coded for carrying out port scanning.  
- `run.sh` [(script)](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/src/run.sh) is a Linux shell script designed and written for compiling and running the attack tool.  

The attack sequence and the observed outputs after carrying out an attack are discussed in the following subsections.  



### Attack Sequence  

Overall attack is carried out in several steps. Each of the programs and scripts mentioned above plays its role in carrying out the attack. The steps of attack are discussed in the following subsections.  



#### Port Scanning with `port_scanning.cpp`  

Port scanning is carried out with the following piece of code written in `port_scanning.cpp`.  

```markdown
#include<SFML/Network.hpp>

using namespace sf;

bool isPortOpen(const string& ipAddress, int port) {
	return (TcpSocket().connect(ipAddress, port) == Socket::Done);
}
```

[Network module](https://www.sfml-dev.org/documentation/2.5.1/group__network.php) of [Simple and Fast Multimedia Library (SFML)](https://www.sfml-dev.org/) has been used for this purpose. `isPortOpen()` function takes in a string reference `ipAddress` along with an integer `port` as inputs. Inside this function, a **TCP (Transmission Control Protocol)** connection is established using an instance of [TcpSocket](https://www.sfml-dev.org/documentation/2.5.1/classsf_1_1TcpSocket.php) class via its `connect()` function. This function takes in the string reference `ipAddress` and converts it to an instance of [IpAddress](https://www.sfml-dev.org/documentation/2.5.1/classsf_1_1IpAddress.php) class. After that, it tries to connect the socket to a remote server/host machine with IP address `ipAddress` on port `port`. Then, the returned value from `connect()` function is compared with a predefined `Socket::Done` status code which means the socket has sent/received the data. TCP connection is successfully established with remote server/host machine on specified port, that is, the specified port is open on that machine if `connect()` function returns `Socket::Done`. Finally, the boolean value from the aforementioned comparison is returned from `isPortOpen()` function.  

Inside `port_scanning.cpp`, the `main()` function takes in IP address of remote server/host machine along with list of ports to be scanned as string inputs either from console or command line. Then, these inputs are processed with other user-defined functions. Finally, port scanning is carried out targeting the specified ports on remote server/host machine.  



#### OS Fingerprinting with `os_fingerprinting.py`  

Inside `main()` function of `port_scanning.cpp`, OS fingerprinting is carried out after port scanning with the following piece of code.  

```markdown
system(("sudo python os_fingerprinting.py "+ipAddress).c_str());
```

`system()` function is used to invoke an operating system command from a C++ program. So basically, the Python script `os_fingerprinting.py` is invoked and executed from C++ file `port_scanning.cpp`. The IP address of the target server/host machine is provided and the command is invoked with root privilege.  



OS fingerprinting is carried out with the following pieces of code written in `os_fingerprinting.py`.  

```markdown
from scapy.all import *  
from scapy.layers.inet import IP, ICMP

packet = IP(dst=sys.argv[1])/ICMP()
response = sr1(packet, timeout=2, verbose=False)
```

Python module [Scapy](https://scapy.readthedocs.io/en/latest/introduction.html) has been used for this purpose. Scapy is a Python interactive packet manipulation program that enables its users to send, sniff, dissect, and forge network packets. Inside `os_fingerprinting.py` script, `packet` is crafted with **IP (Internet Protocol)** and **ICMP (Internet Control Message Protocol)** layers. IP address of remote server/host machine (`sys.argv[1]`) is set in `dst` field of IP layer. Here, passive OS fingerprinting is carried out with **ICMP echo/Ping messages**. Ping messages are used to find out the availability of a server/host machine on a computer network. After crafting `packet`, ICMP echo request is sent to target server/host machine with `sr1` function. `sr1` function takes in `packet` as one of its inputs and requires root privilege to execute. The function returns ICMP echo reply which is captured in `response`.  



```markdown
if response == None:
    print('./{}: No Response from {}.\n'.format(sys.argv[0], sys.argv[1]))
elif IP in response:
    if response.getlayer(IP).ttl <= 64:
        os_guess = 'Linux/ FreeBSD(v5)/ MacOS'
    elif response.getlayer(IP).ttl <= 128:
        os_guess = 'Windows'
    else:
        os_guess = 'Cisco/ Solaris/ SunOS/ FreeBSD(v3.4, v4.0)/ HP-UX(v10.2, v11)'
```

After capturing ICMP echo reply in `response`, it is analyzed to guess the operating system running on target server/host machine. For this purpose, **TTL (Time to Live) or Hop Count** field of IP layer is examined. TTL is a mechanism which limits the lifespan of data in a computer network. It simply means how long a resolver is supposed to cache the DNS query before the query expires and a new one needs to be done. This TTL value differs among different operating systems which comes in handy while guessing OS running on remote server/host machine. So basically, TTL value of IP layer inside ICMP echo reply is examined to carry out remote OS fingerprinting since this particular TTL value is set by the OS running on remote server/host machine. The default TTL values for different operating systems can be found [here](https://subinsb.com/default-device-ttl-values/).  



#### Running Attack Tool with `run.sh`  

The Linux shell script `run.sh` builds raw executable from `port_scanning.cpp` by compilation and linking. Then, it runs the raw executable to carry out port scanning followed by OS fingerprinting.  



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

