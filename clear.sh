ps -elf | grep "receive" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
ps -elf | grep "simple_switch" | awk '{print $4}' | while read line; do sudo kill -9 $line; done
ps -elf | grep "tre_controller" | awk '{print $4}' | while read line; do sudo kill -9 $line; done

sudo /home/p4/behavioral-model/tools/veth_teardown.sh

rm -rf build