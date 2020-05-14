#!/bin/bash

num_of_packets=(500)
num_of_in=(2 4)

# 2 ingress switch
for i in ${num_of_packets[@]}; do
    date; echo "Test: 2 ingress switch, ${i} packets"
    sudo python receive2.py --fname=in2_pktnum${i} > logs/recv2_in2_pktnum${i} & # retransmission ratio, listen veth5 recv
    sudo python receive3.py --fname=in2_pktnum${i} > logs/recv_in2_pktnum${i} & # reduction ratio, listen veth3, 9
    gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress.json"
    gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 -i 10@veth10 --log-console --thrift-port 9091 p4json/ingress.json"
    gnome-terminal --command="sudo simple_switch --device-id 3 -i 2@veth3 -i 1@veth4 -i 3@veth9 -i 10@veth16 -i 4@veth15 --log-console --thrift-port 9092 p4json/egress.json"
    sleep 3
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < ruleeg
    sleep 1
    gnome-terminal --command="sudo python send_finefoods2_1.py --fname=in2_1_pktnum${i} --pktnum=${i} --ing=2" # send 1, 7
    sudo python send_finefoods2_2.py --fname=in2_2_pktnum${i} --pktnum=${i} --ing=2
    sleep 15
    ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    sleep 5
done

# 4 ingress switch
for i in ${num_of_packets[@]}; do
    date; echo "Test: 4 ingress switch, ${i} packets"
    sudo python receive2.py --fname=in4_pktnum${i} > logs/recv2_in4_pktnum${i} & # retransmission ratio, listen veth5 recv
    sudo python receive4.py --fname=in4_pktnum${i} > logs/recv_in4_pktnum${i} & # recv veth 3 9 13 15, tre packets //reduction ratio
    gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 --log-console --thrift-port 9090 p4json/ingress.json"
    gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 --log-console --thrift-port 9091 p4json/ingress.json"
    gnome-terminal --command="sudo simple_switch --device-id 4 -i 1@veth10 -i 3@veth12 --log-console --thrift-port 9093 p4json/ingress.json"
    gnome-terminal --command="sudo simple_switch --device-id 5 -i 1@veth16 -i 3@veth14 --log-console --thrift-port 9094 p4json/ingress.json"
    gnome-terminal --command="sudo simple_switch --device-id 3 -i 2@veth3 -i 1@veth4 -i 3@veth9 -i 4@veth15 -i 5@veth13  --log-console --thrift-port 9092 p4json/egress.json"
    sleep 3
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9093 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9094 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < ruleeg
    sleep 1
    sudo python send_finefoods2_1.py --fname=in4_pktnum${i}_1 --pktnum=${i} --ing=4 & # send 1, 7
    sudo python send_finefoods2_2.py --fname=in4_pktnum${i}_2 --pktnum=${i} --ing=4 & # send 1, 7
    sudo python send_finefoods2_3.py --fname=in4_pktnum${i}_3 --pktnum=${i} --ing=4 & # send 1, 7
    sudo python send_finefoods2_4.py --fname=in4_pktnum${i}_4 --pktnum=${i} --ing=4
    sleep 15
    ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    sleep 5
done