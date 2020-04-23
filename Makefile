override CURRENT_DIR := $(patsubst %/,%, $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

override SOURCE_DIR := $(CURRENT_DIR)/src
override BUILD_DIR ?= $(CURRENT_DIR)/build
override INCLUDE_DIR := $(CURRENT_DIR)/include



override SOURCE_DIRS := \
		$(SOURCE_DIR)/api 


SCL_DIR = $(CURRENT_DIR)
include $(CURRENT_DIR)/scripts/scl.mk

override INCLUDE_DIRS := $(SCL_INCLUDES)

# TARGET_DIRS := $(patsubst $(SOURCE_DIR)/%,$(BUILD_DIR)/%, $(SOURCE_DIRS))

override SOURCES := $(foreach dir,$(SOURCE_DIRS),$(wildcard $(dir)/*.c))

override INCLUDES := $(foreach dir,$(INCLUDE_DIRS),$(wildcard $(dir)/*.h))

override OBJS := $(subst $(SOURCE_DIR),$(BUILD_DIR),$(SOURCES:.c=.o))

################################################################################
#                        COMPILATION FLAGS
################################################################################

override CFLAGS += $(foreach dir,$(INCLUDE_DIRS),-I $(dir))

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

libscl.a: $(OBJS)
	$(HIDE) $(HIDE) mkdir -p $(BUILD_DIR)/lib
	$(HIDE) $(AR) $(ARFLAGS) $(BUILD_DIR)/lib/libscl.a $(OBJS)

$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.c
	$(HIDE) mkdir -p $(dir $@)
	$(HIDE) $(CC) $(CFLAGS) -c -o $@ $<

.PHONY : clean
clean:
	rm -rf $(BUILD_DIR)
