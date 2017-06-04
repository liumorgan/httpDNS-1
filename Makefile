CC := gcc
CFLAGS := -O3 -pie -Wall 
#如果是安卓编译
ifeq ($(ANDROID_DATA),/data)
	SHELL = /system/bin/sh
endif

all : 
	$(CC) $(CFLAGS) $(DEFS) -o dns-client http-dns-client.c
	$(CC) $(CFLAGS) $(DEFS) -o dns-server http-dns-server.c
	strip dns-client dns-server
	-chmod 777 dns-client dns-sercer 2>&- 
