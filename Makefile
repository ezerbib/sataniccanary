PLUGIN_SOURCE_FILES = sataniccanary.cpp
PLUGIN_OBJECT_FILES = sataniccanary.o
PLUGIN = sataniccanary.so

CC  = gcc
GCC = g++
GCCPLUGINS_DIR = $(shell $(CC) -print-file-name=plugin)
CXXFLAGS += -I$(GCCPLUGINS_DIR)/include -std=gnu++11 -shared -fPIC -g -O0 \
          -Wall -pedantic -Wl,--export-all-symbols -Wno-literal-suffix -fno-rtti   $(EXTRA_CFLAGS)

all: $(PLUGIN)

$(PLUGIN): $(PLUGIN_OBJECT_FILES)
	$(GCC) -g -shared $^ -o $@ $(CFLAGS)
                    
test: clean $(PLUGIN) test.c
	$(GCC) test.c -o $@ -fplugin=./$(PLUGIN) \
        -g3 -O0 $(EXTRA_ARGS)

clean:
	rm -fv $(PLUGIN) *.o test

# Some stuff I use for debugging
#debug:
#	exec gdb --args /home/enferex/docs/edu/go/dev/gcc-obj/gcc/cc1 \
#        -fplugin=./$(PLUGIN) test.c
