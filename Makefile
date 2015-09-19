PI_SIZE = 16

target = main_$(PI_SIZE)
obj = pi$(PI_SIZE)-cipher.o
size = size

ifdef CROSS
  CC = $(CROSS)-gcc
  target := $(target)_$(CROSS)
  obj = pi$(PI_SIZE)-cipher_$(CROSS).o
  size := $(CROSS)-size
endif

OPT = -Os

CFLAGS = "-DPI_SIZE=$(PI_SIZE)" $(OPT)

all: test report

clean:
	rm -f $(target) $(obj)
	
test: $(target)

$(target): main.c $(obj)
	$(CC) $(CFLAGS) -o $@ $^
	
$(obj): pi-cipher.c pi-cipher.h pi$(PI_SIZE)_parameter.h
	$(CC) $(CFLAGS) -c -o $@ $<

report: $(obj)
	$(size) $^


