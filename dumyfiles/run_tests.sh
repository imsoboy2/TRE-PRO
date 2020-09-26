#!/bin/bash

# num_of_packets=(1000 5000 10000 20000)
num_of_packets=(100 200)
cache_size=(8 16 32 64)
chunk_size=(16 32 48)
num_of_buckets=(4 8 12 16)
dist_type=("z" "u" "g")

echo "-----Test start!----"

# cache size
for i in ${cache_size[@]}; do
    for j in ${num_of_packets[@]}; do
        echo ""
        date; echo "Test: cache size = " $i ", number of packet = " $j
        sudo python receive.py --fname=cache${i}_pktnum${j} > logs/cache_receive_${i}_${j} &
        sudo python Netre/tre_controller.py --cache=${i} > logs/cache_tre_${i}_${j} &
        sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/tre_ingress_cache${i}.json > logs/cache_bmv2_${i}_${j} &
        sleep 3
        /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rule
        sudo python send_finefoods.py --fname=cache${i}_pktnum${j} --pktnum=$j
        ps -elf | grep "receive.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "tre_controller.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        sleep 10
    done
done

# chunk size
for i in ${chunk_size[@]}; do
    for j in ${num_of_packets[@]}; do
        echo ""
        date; echo "Test: chunk size = " $i ", number of packet = " $j
        sudo python receive.py --fname=chunk${i}_pktnum${j} > logs/chunk_receive_${i}_${j} &
        sudo python Netre/tre_controller.py --chunk=${i} > logs/chunk_tre_${i}_${j} &
        sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/tre_ingress_chunk${i}.json > logs/chunk_bmv2_${i}_${j} &
        sleep 3
        /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rule
        sudo python send_finefoods.py --fname=chunk${i}_pktnum${j} --pktnum=$j
        ps -elf | grep "receive.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "tre_controller.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        sleep 10
    done
done

# number of buckets
for i in ${num_of_buckets[@]}; do
    for j in ${num_of_packets[@]}; do
        echo ""
        date; echo "Test: number of buckets = " $i ", number of packet = " $j
        sudo python receive.py --fname=bkt${i}_pktnum${j} > logs/bkt_receive_${i}_${j} &
        sudo python Netre/tre_controller.py --bktnum=${i} > logs/bkt_tre_${i}_${j} &
        sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/tre_ingress.json > logs/bkt_bmv2_${i}_${j} &
        sleep 3
        /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rule
        sudo python send_finefoods.py --fname=bkt${i}_pktnum${j} --pktnum=$j
        ps -elf | grep "receive.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "tre_controller.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
        sleep 10
    done
done

# # distribution type
# for i in ${dist_type[@]}; do
#     for j in ${num_of_packets[@]}; do
#         printf "dist%s_pktnum%d\n" $i $j
#     done
# done