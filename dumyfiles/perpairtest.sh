#!/bin/bash

# num_of_packets=(20000 500 5000 1000 10000)
num_of_packets=(20000)
num_of_in=(2)

# 2 ingress switch
for i in ${num_of_packets[@]}; do
    # date; echo "Test: 4 ingress switch, 1 bucket, ${i} packets"
    # sudo python receive2.py --fname=in4_pktnum${i} > logs/recv2_in1_pktnum${i} & # retransmission ratio, listen veth34 recv
    # sudo python receive3.py --fname=in4_pktnum${i} > logs/recv_in1_pktnum${i} & # reduction ratio, listen veth3, 9, 15, 19
    # gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress_13_chunk8.json"
    # gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 -i 10@veth10 --log-console --thrift-port 9091 p4json/ingress_13_chunk8.json"
    # gnome-terminal --command="sudo simple_switch --device-id 4 -i 1@veth12 -i 3@veth14 -i 10@veth10 --log-console --thrift-port 9092 p4json/ingress_13_chunk8.json"
    # gnome-terminal --command="sudo simple_switch --device-id 5 -i 1@veth16 -i 3@veth18 -i 10@veth10 --log-console --thrift-port 9093 p4json/ingress_13_chunk8.json"
    # gnome-terminal --command="sudo simple_switch --device-id 3 -i 1@veth35 -i 2@veth3 -i 3@veth9 -i 4@veth15 -i 5@veth19 --log-console --thrift-port 9094 p4json/egress.json"
    # sleep 3
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein1
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein1
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < rulein1
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9093 < rulein1
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9094 < ruleeg
    # sleep 1
    # gnome-terminal --command="sudo python send_finefoods2_1.py --fname=in4_1_pktnum${i} --pktnum=${i} --ing=4" # send 0
    # gnome-terminal --command="sudo python send_finefoods2_2.py --fname=in4_2_pktnum${i} --pktnum=${i} --ing=4" # send 6
    # gnome-terminal --command="sudo python send_finefoods2_3.py --fname=in4_3_pktnum${i} --pktnum=${i} --ing=4" # send 12
    # sudo python send_finefoods2_4.py --fname=in4_4_pktnum${i} --pktnum=${i} --ing=4 # send veth16
    # sleep 20
    # ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    # ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    # sleep 5

    date; echo "Test: 8 ingress switch, 1 bucket, ${i} packets"
    sudo python receive2.py --fname=in8_0_pktnum${i} > logs/recv2_in1_pktnum${i} & # retransmission ratio, listen veth34 recv
    sudo python receive2_1.py --fname=in8_1_pktnum${i} > logs/recv2_in1_pktnum${i} & # retransmission ratio, listen veth37 recv
    sudo python receive3.py --fname=in8_pktnum${i} > logs/recv_in1_pktnum${i} & # reduction ratio, listen veth3, 9, 15, 19, 23, 27, 29, 33
    gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 -i 10@veth10 --log-console --thrift-port 9091 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 4 -i 1@veth12 -i 3@veth14 -i 10@veth10 --log-console --thrift-port 9092 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 5 -i 1@veth16 -i 3@veth18 -i 10@veth10 --log-console --thrift-port 9093 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 6 -i 1@veth20 -i 3@veth22 -i 10@veth10 --log-console --thrift-port 9094 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 7 -i 1@veth24 -i 3@veth26 -i 10@veth10 --log-console --thrift-port 9095 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 8 -i 1@veth4 -i 3@veth28 -i 10@veth10 --log-console --thrift-port 9096 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 9 -i 1@veth30 -i 3@veth32 -i 10@veth10 --log-console --thrift-port 9097 p4json/ingress_13_chunk8.json"
    gnome-terminal --command="sudo simple_switch --device-id 3 -i 1@veth35 -i 10@veth36 -i 2@veth3 -i 3@veth9 -i 4@veth15 -i 5@veth19 -i 6@veth23 -i 7@veth27 -i 8@veth29 -i 9@veth33 --log-console --thrift-port 9098 p4json/egress1.json"
    sleep 3
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9093 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9094 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9095 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9096 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9097 < rulein1
    /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9098 < ruleeg
    sleep 1
    gnome-terminal --command="sudo python send_finefoods2_1.py --fname=in8_1_pktnum${i} --pktnum=${i} --ing=8" # send 0
    gnome-terminal --command="sudo python send_finefoods2_2.py --fname=in8_2_pktnum${i} --pktnum=${i} --ing=8" # send 6
    gnome-terminal --command="sudo python send_finefoods2_3.py --fname=in8_3_pktnum${i} --pktnum=${i} --ing=8" # send 12
    gnome-terminal --command="sudo python send_finefoods2_4.py --fname=in8_4_pktnum${i} --pktnum=${i} --ing=8" # send 16
    gnome-terminal --command="sudo python send_finefoods2_5.py --fname=in8_5_pktnum${i} --pktnum=${i} --ing=8" # send 20
    gnome-terminal --command="sudo python send_finefoods2_6.py --fname=in8_6_pktnum${i} --pktnum=${i} --ing=8" # send 24
    gnome-terminal --command="sudo python send_finefoods2_7.py --fname=in8_7_pktnum${i} --pktnum=${i} --ing=8" # send 4
    sudo python send_finefoods2_8.py --fname=in8_8_pktnum${i} --pktnum=${i} --ing=8 # send veth30
    sleep 30
    ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    # sleep 5

    # date; echo "Test: 2 ingress switch, 2 buckets, ${i} packets"
    # sudo python receive2.py --fname=in2_pktnum${i} > logs/recv2_in2_pktnum${i} & # retransmission ratio, listen veth5 recv
    # sudo python receive3.py --fname=in2_pktnum${i} > logs/recv_in2_pktnum${i} & # reduction ratio, listen veth3, 9
    # gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress_13_chunk8.json"
    # gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 -i 10@veth10 --log-console --thrift-port 9091 p4json/ingress_13_chunk8.json"
    # gnome-terminal --command="sudo simple_switch --device-id 3 -i 2@veth3 -i 1@veth4 -i 3@veth9 -i 10@veth16 -i 4@veth15 --log-console --thrift-port 9092 p4json/egress.json"
    # sleep 3
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein2_1
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein2_2
    # /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < ruleeg2
    # sleep 1
    # gnome-terminal --command="sudo python send_finefoods2_1.py --fname=in2_1_pktnum${i} --pktnum=${i} --ing=2" # send 1
    # sudo python send_finefoods2_2.py --fname=in2_2_pktnum${i} --pktnum=${i} --ing=2 # send veth7
    # sleep 15
    # ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    # ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
    # sleep 5
done

# # 4 ingress switch
# for i in ${num_of_packets[@]}; do
#     date; echo "Test: 4 ingress switch, ${i} packets"
#     sudo python receive2.py --fname=in4_pktnum${i} > logs/recv2_in4_pktnum${i} & # retransmission ratio, listen veth5 recv
#     sudo python receive4.py --fname=in4_pktnum${i} > logs/recv_in4_pktnum${i} & # recv veth 3 9 13 15, tre packets //reduction ratio
#     gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 --log-console --thrift-port 9090 p4json/ingress.json"
#     gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 --log-console --thrift-port 9091 p4json/ingress.json"
#     gnome-terminal --command="sudo simple_switch --device-id 4 -i 1@veth10 -i 3@veth12 --log-console --thrift-port 9093 p4json/ingress.json"
#     gnome-terminal --command="sudo simple_switch --device-id 5 -i 1@veth16 -i 3@veth14 --log-console --thrift-port 9094 p4json/ingress.json"
#     gnome-terminal --command="sudo simple_switch --device-id 3 -i 2@veth3 -i 1@veth4 -i 3@veth9 -i 4@veth15 -i 5@veth13  --log-console --thrift-port 9092 p4json/egress.json"
#     sleep 3
#     /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein1
#     /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein1
#     /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9093 < rulein1
#     /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9094 < rulein1
#     /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < ruleeg
#     sleep 1
#     sudo python send_finefoods2_1.py --fname=in4_pktnum${i}_1 --pktnum=${i} --ing=4 & # send 1, 7
#     sudo python send_finefoods2_2.py --fname=in4_pktnum${i}_2 --pktnum=${i} --ing=4 & # send 1, 7
#     sudo python send_finefoods2_3.py --fname=in4_pktnum${i}_3 --pktnum=${i} --ing=4 & # send 1, 7
#     sudo python send_finefoods2_4.py --fname=in4_pktnum${i}_4 --pktnum=${i} --ing=4
#     sleep 15
#     ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
#     ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
#     sleep 5
# done