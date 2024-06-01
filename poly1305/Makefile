# SDK Configuration
NFP_SDK_DIR ?= /opt/netronome
NFP_STD_LIB ?= $(NFP_SDK_DIR)/components/standardlibrary
PICO_CODE   ?= $(NFP_STD_LIB)/picocode/nfp6000/catamaran/catamaran.npfw

NFAS ?= $(NFP_SDK_DIR)/bin/nfas
NFCC ?= $(NFP_SDK_DIR)/bin/nfcc
NFLD ?= $(NFP_SDK_DIR)/bin/nfld

# Project Configuration
SRC_DIR  := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BASE_DIR ?= $(realpath $(SRC_DIR)/..)

MICROC_BLOCKS_DIR := $(BASE_DIR)/microc/blocks
MICROC_LIBS_DIR   := $(BASE_DIR)/microc/lib
MICROC_INC_DIR    := $(BASE_DIR)/microc/include

# Compiler/Linker options
CHIP ?= nfp-4xxx-b0
PKT_NBI_OFFSET ?= 64

NFASFLAGS ?= -t -W3 -R -lm 0 -C -chip $(CHIP)
NFLDFLAGS ?= -chip $(CHIP)
NFCCFLAGS ?= -W3 -chip $(CHIP) -Qspill=9 -Qnn_mode=1 -Qno_decl_volatile -Qnctx_mode=8

FW_BUILD        := $(SRC_DIR)
FW_FW           := $(SRC_DIR)
FIRMWARE_DIR    := $(BASE_DIR)/microc
NFCC_BASE_INC   := -I. -I$(MICROC_LIBS_DIR) -I$(MICROC_INC_DIR)
NFAS_BASE_FLAGS := $(NFASFLAGS)
NFLD_BASE_FLAGS := $(NFLDFLAGS)
NFAS_BASE_INC   := -I. -I$(MICROC_BLOCKS_DIR) -I$(MICROC_LIBS_DIR) -I$(MICROC_INC_DIR) -I$(NFP_STD_LIB)/microcode/src -I$(NFP_STD_LIB)/include

.PHONY: clean cleanall load

all: poly1305.fw

load: poly1305.fw
	@echo ---------------------------
	@echo load firmware
	@echo ---------------------------
	sudo ./init/run.sh reload poly1305.fw

poly1305.fw: poly1305_obj.list blm_obj.list
	@echo ---------------------------
	@echo linking $@
	@echo ---------------------------
	$(NFLD) $(NFLDFLAGS) -mip -rtsyms \
	-o $(SRC_DIR)/$@ -map $(SRC_DIR)/poly1305.map \
	-u i32.me0  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me1  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me2  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me3  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me4  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me5  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me6  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me7  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me8  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me9  $(SRC_DIR)/poly1305_obj.list \
	-u i32.me10 $(SRC_DIR)/poly1305_obj.list \
	-u i32.me11 $(SRC_DIR)/poly1305_obj.list \
	-u i33.me0  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me1  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me2  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me3  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me4  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me5  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me6  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me7  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me8  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me9  $(SRC_DIR)/poly1305_obj.list \
	-u i33.me10 $(SRC_DIR)/poly1305_obj.list \
	-u i33.me11 $(SRC_DIR)/poly1305_obj.list \
	-u i34.me0  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me1  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me2  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me3  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me4  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me5  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me6  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me7  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me8  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me9  $(SRC_DIR)/poly1305_obj.list \
	-u i34.me10 $(SRC_DIR)/poly1305_obj.list \
	-u i34.me11 $(SRC_DIR)/poly1305_obj.list \
	-u i35.me0  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me1  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me2  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me3  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me4  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me5  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me6  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me7  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me8  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me9  $(SRC_DIR)/poly1305_obj.list \
	-u i35.me10 $(SRC_DIR)/poly1305_obj.list \
	-u i35.me11 $(SRC_DIR)/poly1305_obj.list \
	-u i36.me0  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me1  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me2  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me3  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me4  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me5  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me6  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me7  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me8  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me9  $(SRC_DIR)/poly1305_obj.list \
	-u i36.me10 $(SRC_DIR)/poly1305_obj.list \
	-u i36.me11 $(SRC_DIR)/poly1305_obj.list \
	-u i48.me0 $(SRC_DIR)/blm_obj.list \
	-i i8 -e $(PICO_CODE)

poly1305_obj.list: main.c
	@echo ---------------------------
	@echo compile $@
	@echo ---------------------------
	$(NFCC) -Fo$(SRC_DIR)/ -Fe$(SRC_DIR)/$@ $(NFCCFLAGS) \
	$(NFCC_BASE_INC) -FIconfig.h \
	$(NFP_STD_LIB)/microc/src/rtl.c $(NFP_STD_LIB)/microc/src/intrinsic.c \
	$(MICROC_LIBS_DIR)/nfp/libnfp.c $(MICROC_LIBS_DIR)/pkt/libpkt.c $(MICROC_LIBS_DIR)/std/libstd.c $(MICROC_LIBS_DIR)/net/libnet.c \
	$(SRC_DIR)/main.c

blm_obj.list:
	@echo ---------------------------
	@echo compile $@
	@echo ---------------------------
	$(NFAS) $(NFASFLAGS) \
	-DBLM_CUSTOM_CONFIG -DSINGLE_NBI -DPKT_NBI_OFFSET=$(PKT_NBI_OFFSET) \
	-DBLM_BLQ_EMEM_TYPE=emem -DNBII=8 -DBLM_INSTANCE_ID=0 \
	-DBLM_INIT_EMU_RINGS -DNFP_LIB_ANY_NFAS_VERSION \
	$(NFAS_BASE_INC) -I$(MICROC_BLOCKS_DIR)/blm -I$(MICROC_BLOCKS_DIR)/blm/_h -I$(MICROC_BLOCKS_DIR)/blm/_uc \
	-o $(SRC_DIR)/$@ $(MICROC_BLOCKS_DIR)/blm/blm_main.uc

clean:
	@rm -rf *.list *.uci *.ucp *.obj

cleanall: clean
	@rm -rf *.fw *.map err.log
