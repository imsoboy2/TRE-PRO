BMV2_SWITCH_EXE = simple_switch_grpc
NO_P4 = true
P4C_ARGS = --p4runtime-files $(basename $@).p4.p4info.txt

BUILD_DIR = ../build
PCAP_DIR = pcaps
LOG_DIR = logs

TOPO = topology.json
P4C = p4c-bm2-ss
RUN_SCRIPT = ~/tutorials/utils/run_exercise.py

SOURCES = ../build/tre_ingress.json ../build/tre_egress.json ../build/basic.json
source := $(wildcard *.p4)
outfile := $(source:.p4=.json)

compiled_json := $(BUILD_DIR)/$(outfile)

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(compiled_json)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

all: run

run: build
	sudo python $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo mn -c

build: dirs $(SOURCES)

../build/tre_ingress.json: ../p4src/tre_ingress.p4
	$(P4C) --target bmv2 --p4v 16 $(P4C_ARGS) -o $@ $<

../build/tre_egress.json: ../p4src/tre_egress.p4
	$(P4C) --target bmv2 --p4v 16 $(P4C_ARGS) -o $@ $<

../build/basic.json: ../p4src/basic.p4
	$(P4C) --target bmv2 --p4v 16 $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
