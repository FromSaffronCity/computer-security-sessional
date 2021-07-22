#!/bin/bash

echo -e "\n-------------------------------------------"
echo "|    Port Scanner & OS Version Guesser    |"
echo -e "-------------------------------------------"

if [ $# -eq 2 ]; then
    # port scanning & os fingerprinting
    # building raw executable port.scanner from source code port_scanning.cpp by compilation & linking
    g++ -c port_scanning.cpp
    g++ port_scanning.o -o port.scanner -lsfml-network -lsfml-system

    # running port.scanner & running python script os_fingerprinting.py with root privilege
    ./port.scanner $1 $2

    # removing object code port_scanning.o & raw executable port.scanner
    rm port_scanning.o port.scanner

    echo -e "-------------------------------------------"
    echo "|              Thank You !!!              |"
    echo -e "-------------------------------------------\n"
else
    echo -e "\nUsage: $0 (or bash $0) ipAddress ports"
    echo -e "Examples:"
    echo -e "\t$0  localhost 80"
    echo -e "\t$0 127.0.0.1 80,443"
    echo -e "\tbash $0 scanme.nmap.org 21-25"
    echo -e "\tbash $0 45.33.32.156 21-25,80,443\n"

    echo -e "-------------------------------------------"
    echo "|              Thank You !!!              |"
    echo -e "-------------------------------------------\n"

    exit 1
fi
