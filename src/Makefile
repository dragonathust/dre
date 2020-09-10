
CC      = ${CROSS_COMPILE}gcc
LD      = ${CROSS_COMPILE}ld
AS      = ${CROSS_COMPILE}as

CFLAGS  = -Wall -g -O2
LDFLAGS = -lpthread -lrt
CINCFLAGS = -I ../include

TARGET = daemon
OBJS = kvm.o vcpu.o memory.o hostcall.o file.o net.o family.o process.o shm.o main.o misc.o

ifeq ($(TEST),true)
CFLAGS +=  -DTEST
TARGET += test.bin
endif

%.o: %.c
	$(CC) $(CINCFLAGS) -c -o $*.o $(CFLAGS)  $<

%.o: %.C
	$(CC) $(CINCFLAGS) -c -o $*.o $(CFLAGS)  $<

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

test.bin: test.o
	ld --oformat binary -N -e _start -o test.bin test.o

test.o: code32.s
	as -o $@ $^

clean:
	rm -f *.o *.bin $(TARGET)

