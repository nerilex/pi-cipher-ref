PI_SIZES = 16 32 64

PI_SIZE = 16

target = main_$(1)
obj = pi$(1)-cipher.o
bench = bench_$(1)
asm = pi$(1)-cipher.s
precomp = precomp_$(1)
simple = simple_$(1)

size = size

ifdef CROSS
  CC = $(CROSS)-gcc
  target := $(target)_$(CROSS)
  obj = pi$(PI_SIZE)-cipher_$(CROSS).o
  size := $(CROSS)-size
endif

OPT = -O3

CFLAGS = "-DPI_SIZE=$(PI_SIZE)" -g $(OPT) -march=native -Wall -Warray-bounds $(USER_OPTS)

.PHONY: all
.PHONY: test
.PHONY: report
.PHONY: clean
.PHONY: precomp
.PHONY: run
.PHONY: simple

all: test report
	
test: $(foreach PI_SIZE,$(PI_SIZES), test_$(PI_SIZE))

report: $(foreach PI_SIZE,$(PI_SIZES), report_$(PI_SIZE))

clean: $(foreach PI_SIZE,$(PI_SIZES), clean_$(PI_SIZE))

precomp: $(foreach PI_SIZE,$(PI_SIZES), $(call precomp,$(PI_SIZE)))

run: $(foreach PI_SIZE,$(PI_SIZES), run_$(PI_SIZE))

simple: $(foreach PI_SIZE,$(PI_SIZES), simple_$(PI_SIZE))


%.s: %.c
	$(CC) $(CFLAGS) -c -Wa,-adghlms -g $< > $@

%.pdf: %.ps
	ps2pdf $<
	
%.ps: %.s
	enscript -B -r -l -f Courier8 -o $@ $<



define Template

$(call target,$(1)): main.c $(call obj,$(1))
	$(CC) $(CFLAGS) -o $$@ $$^

$(call precomp,$(1)): precomp.c $(call obj,$(1))
	$(CC) $(CFLAGS) "-DDEBUG=1" -o $$@ $$^

$(call bench,$(1)): bench.c $(call obj,$(1))
	$(CC) $(CFLAGS) "-DDEBUG=0" -static -o $$@ $$^

$(call simple,$(1)): simple.c $(call obj,$(1))
	$(CC) $(CFLAGS) "-DDEBUG=0" -static -o $$@ $$^

	
$(call obj,$(1)): pi-cipher.c pi-cipher.h pi$(1)_parameter.h
	$(CC) $(CFLAGS) -c -o $$@ $$<

.PHONY: clean_$(1)
.PHONY: test_$(1)
.PHONY: report_$(1)
.PHONY: run_$(1)

$(call asm,$(1)): pi-cipher.c pi-cipher.h pi$(1)_parameter.h
	$(CC) $(CFLAGS) -c -Wa,-adghlms -g $$< > $$@

clean_$(1):
	rm -f $(call target,$(1)) $(call obj,$(1)) $(call bench,$(1)) $(call asm,$(1))
	
test_$(1): $(call target,$(1))

report_$(1): $(obj)
	$(size) $$^

run_$(1): $(call target,$(1))
	./$$<

endef

$(foreach PI_SIZE,$(PI_SIZES), $(eval $(call Template,$(PI_SIZE))))

