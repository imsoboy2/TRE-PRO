date; echo "Test: per pair"
sudo python receive.py --fname=recv1_perpair > logs/receive1 &
sudo python receive2.py > logs/recv2_perpair &
sudo python receive3.py --fname=recv3_perpair > logs/receive3 &
gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 3@veth2 -i 10@veth10 --log-console --thrift-port 9090 p4json/tre_ingress_perpair.json"
gnome-terminal --command="sudo simple_switch --device-id 2 -i 1@veth6 -i 3@veth8 -i 10@veth10 --log-console --thrift-port 9091 p4json/tre_ingress_perpair.json"
gnome-terminal --command="sudo simple_switch --device-id 4 -i 1@veth12 -i 3@veth14 -i 10@veth10 --log-console --thrift-port 9093 p4json/tre_ingress_perpair.json"
gnome-terminal --command="sudo simple_switch --device-id 3 -i 2@veth3 -i 1@veth4 -i 3@veth9 -i 10@veth16 -i 4@veth15 --log-console --thrift-port 9092 p4json/tre_egress_perpair.json"
sleep 3
/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rulein1
/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rulein2
/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9093 < rulein2
/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9092 < ruleeg
sleep 1
gnome-terminal --command="sudo python send_finefoods1.py --fname=perpair1 --pktnum=500"
gnome-terminal --command="sudo python send_finefoods2.py --fname=perpair2 --pktnum=500"
gnome-terminal --command="sudo python send_finefoods3.py --fname=perpair3 --pktnum=500"
# ps -elf | grep "receive2.py" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
# ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done