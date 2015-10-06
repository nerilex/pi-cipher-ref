PI_SIZES = 16 32 64

PI_SIZE = 16

target = main_$(1)
obj = pi$(1)-cipher.o
size = size

ifdef CROSS
  CC = $(CROSS)-gcc
  target := $(target)_$(CROSS)
  obj = pi$(PI_SIZE)-cipher_$(CROSS).o
  size := $(CROSS)-size
endif

OPT = -Os

CFLAGS = "-DPI_SIZE=$(PI_SIZE)" -g $(OPT)

all: test report
	
test: $(foreach PI_SIZE,$(PI_SIZES), test_$(PI_SIZE))

report: $(foreach PI_SIZE,$(PI_SIZES), report_$(PI_SIZE))

clean: $(foreach PI_SIZE,$(PI_SIZES), clean_$(PI_SIZE))

run: $(foreach PI_SIZE,$(PI_SIZES), run_$(PI_SIZE))


define Template

$(call target,$(1)): main.c $(call obj,$(1))
	$(CC) $(CFLAGS) -o $$@ $$^
	
$(call obj,$(1)): pi-cipher.c pi-cipher.h pi$(1)_parameter.h
	$(CC) $(CFLAGS) -c -o $$@ $$<

.PHONY: clean_$(1)
.PHONY: test_$(1)
.PHONY: report_$(1)
.PHONY: run_$(1)

clean_$(1):
	rm -f $(call target,$(1)) $(call obj,$(1))
	
test_$(1): $(call target,$(1))

report_$(1): $(obj)
	$(size) $$^

run_$(1): $(call target,$(1))
	./$$<

endef

$(foreach PI_SIZE,$(PI_SIZES), $(eval $(call Template,$(PI_SIZE))))

