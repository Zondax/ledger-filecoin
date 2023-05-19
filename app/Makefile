#*******************************************************************************
#  Ledger App
#  (c) 2019 - 2023 Zondax AG
#  (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

include $(BOLOS_SDK)/Makefile.defines

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN=FIL
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])
ifeq ($(COIN),FIL)
# Main app configuration
APPNAME = "Filecoin"
# Add Legacy Glif / Testnet path
APPPATH = "44'/461'" --path "44'/1'" --path "44'/60'"
else ifeq ($(COIN),FIL_validator)
else
define error_message
COIN value not supported: [$(COIN)]
endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS =  --curve secp256k1 $(COMMON_LOAD_PARAMS) --path $(APPPATH)

NANOS_STACK_SIZE := 1892
include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform

DEFINES       += UNUSED\(x\)=\(void\)x

# App specific
DEFINES += CBOR_NO_FLOATING_POINT
DEFINES += HAVE_HASH HAVE_BLAKE2
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# NanoX SDK does not allow += in APP_SOURCE_PATH or INCLUDES_PATH
CFLAGS += -I$(MY_DIR)/../deps/tinycbor/src
APP_SOURCE_PATH += $(MY_DIR)/../deps/tinycbor-ledger

.PHONY: rust
rust:
	@echo "No rust code"

.PHONY: rust_clean
rust_clean:
	@echo "No rust code"

clean: rust_clean

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: listvariants
listvariants:
	@echo VARIANTS COIN FIL

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version
