all: er-example-server er-example-client er-example-observe-client
# use target "er-plugtest-server" explicitly when requried 

unittest: native-unit-test

CONTIKI=../..


CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\" 
#For saving .s and .o files
#CFLAGS += -save-temps
#For that extra special touch :) 
#CFLAGS += -Wall -Wextra -Wunused-function  

#hotfix for wismote
#ifeq ($(TARGET_MEMORY_MODEL),large)
#  CFLAGS += -mmemory-model=$(TARGET_MEMORY_MODEL)
#  CFLAGS += -mcode-region=far -mdata-region=far -msr20 -mc20 -md20
#  LDFLAGS += -mmemory-model=$(TARGET_MEMORY_MODEL) -mcode-region=far -mdata-region=far -msr20 -mc20 -md20
#endif


# automatically build RESTful resources
REST_RESOURCES_DIR = ./resources
ifndef TARGET
REST_RESOURCES_FILES = $(notdir $(shell find $(REST_RESOURCES_DIR) -name '*.c'))
else
ifeq ($(TARGET), native)
REST_RESOURCES_FILES = $(notdir $(shell find $(REST_RESOURCES_DIR) -name '*.c'))
else
REST_RESOURCES_FILES = $(notdir $(shell find $(REST_RESOURCES_DIR) -name '*.c' ! -name 'res-plugtest*'))
endif
endif

PROJECTDIRS += $(REST_RESOURCES_DIR)
PROJECT_SOURCEFILES += $(REST_RESOURCES_FILES)

# linker optimizations
SMALL=1

#CFLAGS += -Werror
# REST Engine shall use Erbium CoAP implementation
APPS += er-oscoap
APPS += rest-engine

# optional rules to get assembly
#CUSTOM_RULE_C_TO_OBJECTDIR_O = 1
#CUSTOM_RULE_S_TO_OBJECTDIR_O = 1

CONTIKI_WITH_IPV6 = 1 
include $(CONTIKI)/Makefile.include

# minimal-net target is currently broken in Contiki
ifeq ($(TARGET), minimal-net)
CFLAGS += -DHARD_CODED_ADDRESS=\"fdfd::10\"
${info INFO: er-example compiling with large buffers}
CFLAGS += -DUIP_CONF_BUFFER_SIZE=1000
CFLAGS += -DREST_MAX_CHUNK_SIZE=512
CFLAGS += -DCOAP_MAX_HEADER_SIZE=176
CONTIKI_WITH_RPL=0
endif

# optional rules to get assembly
#$(OBJECTDIR)/%.o: asmdir/%.S
#	$(CC) $(CFLAGS) -MMD -c $< -o $@
#	@$(FINALIZE_DEPENDENCY)
#
#asmdir/%.S: %.c
#	$(CC) $(CFLAGS) -MMD -S $< -o $@

# border router rules
$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

connect-router:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 aaaa::1/64

connect-router-cooja:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 -p 60001 aaaa::1/64

connect-router-native:	$(CONTIKI)/examples/ipv6/native-border-router/border-router.native
	sudo $(CONTIKI)/exmples/ipv6/native-border-router/border-router.native -a 127.0.0.1 -p 60001 aaaa::1/64

connect-minimal:
	sudo ip address add fdfd::1/64 dev tap0 
