#!/bin/bash

num_of_packets=(500 1000 5000 10000)
cache_size=(8 16 32 64)
chunk_size=(16 32 64 128)
dist_type=("z80" "z40" "z60")

echo "-----Test start!----"

# # cache size
# for i in ${cache_size[@]}; do
#     for j in ${num_of_packets[@]}; do
#         echo ""
#         date; echo "Test: cache size = " $i ", number of packet = " $j
#         sudo python receive.py --fname=cache${i}_pktnum${j} > logs/cache_receive_${i}_${j} &
#         gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress_cache${i}.json"
#         sleep 3
#         hash_max=`expr ${i} \* 32768 - 1`
#         echo "table_add initiate set_pair => 1 1" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090
#         echo "table_add tre tre_flag_on 1 1 => 0 ${hash_max}" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090
#         sleep 3
#         sudo python send_finefoods1.py --fname=cache${i}_pktnum${j} --pktnum=$j
#         sleep 10
#         ps -elf | grep "receive.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
#         ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
#         sleep 10
#     done
# done

# # chunk size
# for i in ${chunk_size[@]}; do
#     for j in ${num_of_packets[@]}; do
#         echo ""
#         date; echo "Test: chunk size = " $i ", number of packet = " $j
#         sudo python receive.py --fname=chunk${i}_pktnum${j} > logs/chunk_receive_${i}_${j} &
#         gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress_chunk${i}.json"
#         sleep 3
#         hash_max=`expr 33554432 / ${i} - 1`
#         echo "table_add initiate set_pair => 1 1" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090
#         echo "table_add tre tre_flag_on 1 1 => 0 ${hash_max}" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090
#         sleep 3
#         sudo python send_finefoods1.py --fname=chunk${i}_pktnum${j} --pktnum=$j
#         sleep 10
#         ps -elf | grep "receive.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
#         ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
#         sleep 10
#     done
# done

# distribution type
for i in ${dist_type[@]}; do
    for j in ${num_of_packets[@]}; do
        echo ""
        date; echo "Test: distribution size = " $i ", number of packet = " $j
        sudo python receive.py --fname=dist${i}_pktnum${j} > logs/dist_receive_${i}_${j} &
        gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/ingress.json"
        sleep 3
        echo "table_add initiate set_pair => 1 1" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090
        echo "table_add tre tre_flag_on 1 1 => 0 1048575" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090
        sleep 3
        sudo python send_finefoods1.py --fname=dist${i}_pktnum${j} --pktnum=$j --dist=${i}_dist
        sleep 10
        ps -elf | grep "receive.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        sleep 10
    done
done