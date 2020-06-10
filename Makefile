override CURRENT_DIR := $(patsubst %/,%, $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

override SOURCE_DIR := $(CURRENT_DIR)/src
override BUILD_DIR ?= $(CURRENT_DIR)/build

override INCLUDE_DIR := $(CURRENT_DIR)/include

override SOURCE_DIRS := $(SOURCE_DIR)
# API
override SOURCE_DIRS += \
		$(SOURCE_DIR)/api \
		$(SOURCE_DIR)/api/software \
		$(SOURCE_DIR)/api/software/hash \
		$(SOURCE_DIR)/api/hardware 
		
# the version management will be improved, this is just a draft to test
# compilation of the version specific files
ifeq ($(HCA_VERSION),0.5)
override SOURCE_DIRS += \
		$(SOURCE_DIR)/api/hardware/v0.5 \
		$(SOURCE_DIR)/api/hardware/v0.5/hash 
endif

# SCL
override SOURCE_DIRS += \
		$(SOURCE_DIR)/blockcipher \
		$(SOURCE_DIR)/blockcipher/aes \
		$(SOURCE_DIR)/hash \
		$(SOURCE_DIR)/hash/sha

SCL_DIR = $(CURRENT_DIR)
include $(CURRENT_DIR)/scripts/scl.mk

# INCLUDE_DIRS is only use to list includes files and execute check-format.
override INCLUDE_DIRS := $(SCL_INCLUDES) 
 # API
override INCLUDE_DIRS += \
	$(CURRENT_DIR)/include/api \
	$(CURRENT_DIR)/include/api/software \
	$(CURRENT_DIR)/include/api/software/hash \
	$(CURRENT_DIR)/include/api/hardware \
	$(CURRENT_DIR)/include/api/hardware/v0.5 \
	$(CURRENT_DIR)/include/api/hardware/v0.5/hash
 # SCL
override INCLUDE_DIRS += \
	$(CURRENT_DIR)/include/scl

# TARGET_DIRS := $(patsubst $(SOURCE_DIR)/%,$(BUILD_DIR)/%, $(SOURCE_DIRS))

override SOURCES := $(foreach dir,$(SOURCE_DIRS),$(wildcard $(dir)/*.c))

override INCLUDES := $(foreach dir,$(INCLUDE_DIRS),$(wildcard $(dir)/*.h))

override OBJS := $(subst $(SOURCE_DIR),$(BUILD_DIR),$(SOURCES:.c=.o))

################################################################################
#                        COMPILATION FLAGS
################################################################################

override CFLAGS += -I $(INCLUDE_DIR)

override ASFLAGS = $(CFLAGS)

ifeq ($(origin ARFLAGS),default)
	ifeq ($(VERBOSE),TRUE)
		override ARFLAGS :=	cruv
	else
		override ARFLAGS :=	cru
	endif
else
	ifeq ($(VERBOSE),TRUE)
		ARFLAGS ?= cruv
	else
		ARFLAGS ?= cru
	endif
endif

################################################################################
#                               MACROS
################################################################################

ifeq ($(VERBOSE),TRUE)
	HIDE := 
else
	HIDE := @
endif

################################################################################
#                                RULES
################################################################################

libscl.a: $(OBJS) err
	$(HIDE) mkdir -p $(BUILD_DIR)/lib
	$(HIDE) $(AR) $(ARFLAGS) $(BUILD_DIR)/lib/libscl.a $(OBJS)

$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.c err
	$(HIDE) mkdir -p $(dir $@)
	$(HIDE) $(CC) $(CFLAGS) -ggdb3 -c -o $@ $<

.PHONY : check-format
check-format:
	clang-format -i $(SOURCES) $(INCLUDES)

.PHONY: err
err: 
	$(ERR)

.PHONY : clean
clean:
	rm -rf $(BUILD_DIR)
