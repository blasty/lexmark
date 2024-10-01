TOOLCHAIN := arm-linux-musleabi
CC := $(TOOLCHAIN)-gcc

CFLAGS := -Wall -O2 -I./include/

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG=1
endif

all:
	$(CC) $(CFLAGS) -o wtm_oracle src/*.c -static

clean:
	rm -rf wtm_oracle