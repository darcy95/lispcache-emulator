#!/bin/bash 
ipsumdump -t -s -d -S -D -p -l -F --payload -q | awk '(NR > 5 && $2 != "-" && $3 != "-") { print $0; }' | perl lispcache-emulator.pl -m text -t 30 -g 30 -y no -q no -u 0 -h no
