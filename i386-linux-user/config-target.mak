# Automatically generated by configure - do not modify
CONFIG_QEMU_INTERP_PREFIX="/usr/gnemul/qemu-i386"
TARGET_ARCH=i386
TARGET_I386=y
TARGET_ARCH2=i386
TARGET_BASE_ARCH=i386
TARGET_ABI_DIR=i386
CONFIG_USER_ONLY=y
CONFIG_LINUX_USER=y
CONFIG_NOSOFTFLOAT=y
CONFIG_I386_DIS=y
CONFIG_I386_DIS=y
LDFLAGS+=-Wl,-T../config-host.ld -Wl,-T,$(SRC_PATH)/$(ARCH).ld 
QEMU_CFLAGS+=-I$(SRC_PATH)/fpu -I$(SRC_PATH)/tcg -I$(SRC_PATH)/tcg/$(ARCH) 
