#!/bin/bash
# ./main rule add -n name -si 192.168.17.1/24 -sp any -ti 192.168.17.135/24 -tp any -p ICMP -a re -l no
# ./main rule ls
./main nat add -si 192.168.18.128/24 -ti 192.168.5.129 -tp any
./main nat ls