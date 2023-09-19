CFLAGS := -O2 -flto --std=c2x -I.
CC := clang

SRCS := nfcgi.c test.c

OBJS := $(patsubst %.c, build/%.o, $(SRCS))

test-fcgi: build $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter-out $<,$^)

build:
	mkdir -v build

build/%.d: %.c build $(HDRS)
	$(CC) $(CFLAGS) -MM $< -MT $(patsubst %.c, build/%.o, $<) -MF $@

build/%.o: %.c build/%.d
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean

clean:
	rm -rvf build
	rm -vf test-fcgi

ifneq ($(MAKECOMDGOALS),clean)
-include $(patsubst %.c, build/%.d, $(SRCS))
endif
