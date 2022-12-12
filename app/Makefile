#*******************************************************************************
#  Ledger App
#  (c) 2019 - 2022 Zondax AG
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

MAKEFILES_DIR := $(CURDIR)/../deps/ledger-zxlib/makefiles
include $(MAKEFILES_DIR)/Makefile.installer_script

include $(BOLOS_SDK)/Makefile.defines
include $(MAKEFILES_DIR)/Makefile.app_testing

ifndef COIN
COIN=FIL
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])
ifeq ($(COIN),FIL)
# Main app configuration
APPNAME = "Filecoin"
APPPATH = "44'/461'"
else ifeq ($(COIN),FIL_validator)
else
define error_message
COIN value not supported: [$(COIN)]
endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = $(COMMON_LOAD_PARAMS) --path $(APPPATH)

NANOS_STACK_SIZE := 1892
include $(MAKEFILES_DIR)/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

############
# Platform
include $(MAKEFILES_DIR)/Makefile.platform

# App specific
DEFINES += CBOR_NO_FLOATING_POINT

# NanoX SDK does not allow += in APP_SOURCE_PATH or INCLUDES_PATH
CFLAGS += -I$(CURDIR)/../deps/tinycbor/src
APP_SOURCE_PATH += $(CURDIR)/../deps/tinycbor-ledger

include $(MAKEFILES_DIR)/Makefile.c_app
include $(MAKEFILES_DIR)/Makefile.side_loading

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
