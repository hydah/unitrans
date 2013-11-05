# Automatically generated by configure - do not modify
# Configured with: './configure' '--prefix=/usr' '--disable-docs' '--disable-system' '--prefix=/usr' '--target-list=i386-linux-user' '--disable-sdl' '--disable-attr' '--disable-guest-base' '--disable-uuid' '--disable-curses' '--disable-check-utests'
prefix=/usr
bindir=${prefix}/bin
mandir=${prefix}/share/man
datadir=${prefix}/share/qemu
sysconfdir=${prefix}/etc
docdir=${prefix}/share/doc/qemu
confdir=${prefix}/etc/qemu
ARCH=i386
STRIP_OPT=-s
HOST_LONG_BITS=32
CONFIG_POSIX=y
CONFIG_LINUX=y
CONFIG_SLIRP=y
CONFIG_AC97=y
CONFIG_ES1370=y
CONFIG_SB16=y
CONFIG_AUDIO_DRIVERS=oss
CONFIG_OSS=y
CONFIG_BDRV_WHITELIST=
CONFIG_VNC_TLS=y
VNC_TLS_CFLAGS= 
CONFIG_VNC_SASL=y
VNC_SASL_CFLAGS=
CONFIG_VNC_JPEG=y
VNC_JPEG_CFLAGS=
CONFIG_VNC_PNG=y
VNC_PNG_CFLAGS=
CONFIG_FNMATCH=y
VERSION=
PKGVERSION=
SRC_PATH=/home/vhome/heyu/work/unitrans/unitrans-0.8
TARGET_DIRS=i386-linux-user
CONFIG_ATFILE=y
CONFIG_SPLICE=y
CONFIG_INOTIFY=y
CONFIG_BYTESWAP_H=y
CONFIG_CURL=y
CURL_CFLAGS= 
INSTALL_BLOBS=yes
CONFIG_IOVEC=y
CONFIG_GCC_ATTRIBUTE_WARN_UNUSED_RESULT=y
CONFIG_FDATASYNC=y
CONFIG_UNAME_RELEASE=""
CONFIG_ZERO_MALLOC=y
HOST_USB=linux
TOOLS=
ROMS=
MAKE=make
INSTALL=install
INSTALL_DIR=install -d -m0755 -p
INSTALL_DATA=install -m0644 -p
INSTALL_PROG=install -m0755 -p
CC=gcc
HOST_CC=gcc
AR=ar
OBJCOPY=objcopy
LD=ld
CFLAGS=-O2 -g 
QEMU_CFLAGS=-I$(SRC_PATH)/slirp -m32 -fstack-protector-all -Wold-style-definition -I. -I$(SRC_PATH) -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wstrict-prototypes -Wredundant-decls -Wall -Wundef -Wendif-labels -Wwrite-strings -Wmissing-prototypes -fno-strict-aliasing 
HELPER_CFLAGS=-fomit-frame-pointer
LDFLAGS=-Wl,--warn-common -m32 -g 
ARLIBS_BEGIN=
ARLIBS_END=
LIBS+=-lrt -lpthread 
LIBS_TOOLS+=-L/usr/kerberos/lib -lcurl -ldl -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lidn -lssl -lcrypto -lz   
EXESUF=