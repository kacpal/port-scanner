# Port scanner
Program is based on lpcap and lnet libraires. Uses SYN-scan technique to perform the attack. Works only on linux machines and requires lpcap and lnet. Made for educational puproses.

## Installation
Use ```git clone https://github.com/kacpal/port-scanner.git``` to download the repository. Then go to the _port-scanner_ folder and execute ```Make``` to install. Installation requires libnet and libpcap libraires, if you don't have them installed use:<br>```sudo apt-get install libpcap-dev && apt-get install libnet-dev```

## Usage
```
sudo ./portscanner <ip address> [options]
```
Instead of an IP adress, you can also use hostname, e.g. nmap.scanme.org. Due to the SYN-scan technique nature, it is required to run program as root.

## Options
```-p``` Port range. You can type just one port or select a whole range.
<br>```-d``` Device. Libnet should find and select a proper device automatically but if there are problems, you can use this option to select your prefered one.
<br>```-h``` Display help page.

## Example
```
user@linux:~/Directory/port-scanner$ sudo ./portscanner nmap.scanme.org -p 20-30 -d wlan0
======================
PORT    STATE
======================
21      closed
20      closed
23      closed
24      closed
26      closed
25      closed
22      opened
30      closed
28      closed
27      closed
29      closed

Scan completed after 0.34s.
```
