# port-scanner  

This repository contains all the programs coded, reports written, and documentations prepared for the sessional **Term Project** on **Port Scanning** and **OS Fingerprinting**.  

In this project, an attack tool has been designed and implemented for carrying out port scanning and OS fingerprinting on remote server/host machine. The developed tool has been tested on my local machines as well as on [scanme.nmap.org](http://scanme.nmap.org/) keeping in mind that it is **strongly prohibited** to carry out port scanning and OS fingerprinting on remote machine **without the permission of its owner**. For the same reason, **I will not be responsible for any evil and illegal action performed using my code**.  

You will find the details on design and implementation of the attack tool in **reports** section below.  



## reports  

- [Project Design Report](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/design-report/design-report-port-scanner.md)  
- [Project Final/Implementation Report](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/reports/final-report/final-report-port-scanner.md)  



## navigation  

- `docs/` contains all the references and documentations related to this project  
- `reports/` contains design and implementation reports on this project  
- `src/` contains all the programs coded and scripts written for this project  



## guideline  

### getting started  

1. just run the Linux shell script `run.sh` inside `src/` directory with the command  
   `./run.sh <target_IP_address> <list_of_comma_separated_ports>`.  


   example:  

   ```markdown
   ./run.sh 192.168.1.1 21-25,80,443
   bash run.sh scanme.nmap.org 22,53,80,443,1433
   ```

2. You may need to install [SFML](https://www.sfml-dev.org/tutorials/2.5/start-linux.php), [libpcap-dev](https://packages.debian.org/sid/libpcap-dev), and other dependencies if it is necessary.  



## references  

- [Important Websites, Tutorials, and Documentations](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/port-scanner/docs/references.md)  

