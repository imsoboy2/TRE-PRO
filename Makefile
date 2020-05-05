all: run

run: tre_ingress.json tre_egress.json
	gnome-terminal --command="sudo python receive.py"
	gnome-terminal --command="sudo python receive2.py"
	gnome-terminal --command="sudo python Netre/tre_controller.py"
	gnome-terminal --command="sudo python Netre/tre_controller2.py"
	gnome-terminal --command="sudo simple_switch --device-id 1 -i 1@veth0 -i 2@veth2 -i 10@veth10 --log-console --thrift-port 9090 tre_ingress.json"
	gnome-terminal --command="sudo simple_switch --device-id 2 -i 2@veth3 -i 1@veth4 -i 10@veth12 --log-console --thrift-port 9091 tre_egress.json"
	sleep 3
	/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090 < rule
	/home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9091 < rule
	sleep 1
	sudo python send_finefoods.py


tre_ingress.json: Netre/p4src/tre_ingress.p4
	p4c --target bmv2 --arch v1model --std p4-16 Netre/p4src/tre_ingress.p4

tre_egress.json: Netre/p4src/tre_egress.p4
	p4c --target bmv2 --arch v1model --std p4-16 Netre/p4src/tre_egress.p4

clean:
	rm -rf *.json
	rm -rf *.p4i
	rm -rf recvpkt sentpkt