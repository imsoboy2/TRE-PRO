#!/bin/bash

num_of_packets=(500 1000 5000 10000 20000)
dist_type=("z80" "z60" "z40")

echo "-----Test start!----"

for i in ${dist_type[@]}; do
    for j in ${num_of_packets[@]}; do
        echo ""
        date; echo "Test: distribution size = " $i ", number of packet = " $j
        sudo python client/receive_ingress.py --fname=dist${i}_pktnum${j} > build/logs/chunk_receive_${i}_${j} &
        gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 build/netre_ingress.json"
        sleep 3
        /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein
        sleep 3
        sudo python client/send_finefoods.py --fname=dist${i}_pktnum${j} --pktnum=$j --dist=${i}_dist
        sleep 10
        ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        sleep 10
    done
done