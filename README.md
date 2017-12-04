# NetAlarm
A network sniffer that reports instances of port scanning on hosting device and unencrypted login credentials sent over unsecured network protocols (e.g. HTTP, FTP and IMAP).

## Dependencies

    Python v2.7
    Scapy

## Installation

    git clone https://github.com/JohnGee96/NetAlarm.git
    pip install scapy

## Usage

    python netalarm [-h] [-r PCAP_FILE] [-i INTERFACE]

    Optional Arguments:
        -h  -help:      display this help message
        -r PCAP_FILE:   read a pcap file that contains network traffic
        -i INTERFACE    sniff on a ethernet interface (e.g. eth0)

## Example Unsecured Website

- http://www.cs.tufts.edu/~molay/tas/sys
- http://thiscrush.com/login.php
- http://the-internet.herokuapp.com/login
- http://www.latimes.com/hp-2/
- http://www.wejis.com/pa/Search.cfm

## Discussion

Network security has always been a issue neglected by many companies and organizations of all kind. As a result, to this day, there are many services on the net still using unsecured protocols like HTTP. 

In such protocol, all traffic between the host and the client are sent in clear text, including authentication credentials, credit card numbers and other sensitive information. This is very dangerous for users as any third party who tapped onto the users' network can easily obtain users' information.

This tool can be used defensively to monitor the user's network to detect login credential sent over unsecured network protocol. 

For the rest of this discussion, we can focus on detecting authentication credentials sent HTTP. We will make the assumption that most of the unsecured website uses POST HTTP verb to send login credentials.

Since a host can use any data format for transferring login credential, it is hard to make a general mask that capture all login credentials. For example, some of the common structures were "Basic Authentication using Base64 encoding", "JSON" and "Raw Text with key-values pairs".

However, most implementations have some of sort of keys to indicate what type of data it is storing. The best strategy is to capture these keys and the values they linked to. For example, a common implementation for storing login credentials is below:

    User:someUser & Password:somePassword 

Regular expression is a great tool to create a mask that can capture the key-value pairs like above. Below are some features that regular expression should be built to isolate.

    1. Keys can be capitalized in any way.
    2. Keys can be a variant substrings of username and password, including "usr", "user", "usn", "pass", "pw", etc...
    3. Separators that indicate the end of a key-value pair. These are often "\n", "&" and "'" characters.

    
