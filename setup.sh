mkdir -p build/results/reduction
mkdir build/results/retransmission
mkdir build/logs

# make distribution files
num_of_packets=(5000 10000 50000 100000 200000)
dist_type=(80 60 40)
for i in ${dist_type[@]}; do
    for j in ${num_of_packets[@]}; do
        python make_zipf.py --dist=${i} --pktnum=${j}
    done
done

# compile P4 codes
p4c --target bmv2 --arch v1model --std p4-16 p4src/simple_switch/netre_ingress.p4
p4c --target bmv2 --arch v1model --std p4-16 p4src/simple_switch/netre_egress.p4
mv netre_ingress.* build/
mv netre_egress.* build/

# setup virtual eth
sudo /home/p4/behavioral-model/tools/veth_setup.sh