all: sha3sumr64 sha3sumr32 sha3sum64 sha3sum32 sha3sumc

SOURCES_COMMON = \
    Constructions/KeccakDuplex.c \
    Constructions/KeccakSponge.c \
    Modes/KeccakHash.c \
    Tests/sha3sum.c

SOURCES_REFERENCE = \
    $(SOURCES_COMMON) \
    KeccakF-1600/Reference/KeccakF-1600-reference.c \
    Tests/displayIntermediateValues.c

SOURCES_REFERENCE32BI = \
    $(SOURCES_COMMON) \
    KeccakF-1600/Reference/KeccakF-1600-reference32BI.c \
    Tests/displayIntermediateValues.c

SOURCES_OPTIMIZED = \
    $(SOURCES_COMMON)

SOURCES_OPTIMIZED_64 = \
    $(SOURCES_OPTIMIZED) \
    KeccakF-1600/Optimized/KeccakF-1600-opt64.c

SOURCES_INPLACE32BI = \
    $(SOURCES_OPTIMIZED) \
    KeccakF-1600/Optimized/KeccakF-1600-inplace32BI.c

SOURCES_COMPACT = \
    $(SOURCES_OPTIMIZED) \
    KeccakF-1600/Compact/Keccak-compact64.c

HEADERS_COMMON = \
    Constructions/KeccakDuplex.h \
    Constructions/KeccakSponge.h \
    KeccakF-1600/KeccakF-1600-interface.h \
    Tests/sha3sum.h \
    Tests/sha3sum-config.h \
    Modes/KeccakHash.h

HEADERS_REFERENCE = \
    $(HEADERS_COMMON) \
    KeccakF-1600/Reference/KeccakF-1600-reference.h \
    Tests/displayIntermediateValues.h

HEADERS_REFERENCE32BI = $(HEADERS_REFERENCE)

HEADERS_OPTIMIZED = \
    $(HEADERS_COMMON) \
    Common/brg_endian.h

HEADERS_OPTIMIZED_64 = \
    $(HEADERS_OPTIMIZED) \
    KeccakF-1600/Optimized/KeccakF-1600-opt64-settings.h \
    KeccakF-1600/Optimized/KeccakF-1600-unrolling.macros \
    KeccakF-1600/Optimized/KeccakF-1600-64.macros

HEADERS_INPLACE32BI = \
    $(HEADERS_OPTIMIZED)

BINDIR_REFERENCE = bin/reference

$(BINDIR_REFERENCE):
	mkdir -p $(BINDIR_REFERENCE)

BINDIR_REFERENCE32BI = bin/reference32bi

$(BINDIR_REFERENCE32BI):
	mkdir -p $(BINDIR_REFERENCE32BI)

BINDIR_OPTIMIZED_64 = bin/optimized64

$(BINDIR_OPTIMIZED_64):
	mkdir -p $(BINDIR_OPTIMIZED_64)

BINDIR_INPLACE32BI = bin/inplace32BI

$(BINDIR_INPLACE32BI):
	mkdir -p $(BINDIR_INPLACE32BI)

BINDIR_COMPACT = bin/compact

$(BINDIR_COMPACT):
	mkdir -p $(BINDIR_COMPACT)

OBJECTS_REFERENCE = $(addprefix $(BINDIR_REFERENCE)/, $(notdir $(patsubst %.c,%.o,$(SOURCES_REFERENCE))))

OBJECTS_REFERENCE32BI = $(addprefix $(BINDIR_REFERENCE32BI)/, $(notdir $(patsubst %.c,%.o,$(SOURCES_REFERENCE32BI))))

OBJECTS_OPTIMIZED_64 = $(addprefix $(BINDIR_OPTIMIZED_64)/, $(notdir $(patsubst %.c,%.o,$(SOURCES_OPTIMIZED_64))))

OBJECTS_INPLACE32BI = $(addprefix $(BINDIR_INPLACE32BI)/, $(notdir $(patsubst %.c,%.o,$(SOURCES_INPLACE32BI))))

OBJECTS_COMPACT = $(addprefix $(BINDIR_COMPACT)/, $(notdir $(patsubst %.c,%.o,$(SOURCES_COMPACT))))

CC = gcc

CFLAGS_REFERENCE = -DKeccakReference -O -Wno-format-security

CFLAGS_REFERENCE32BI = -DKeccakReference32BI -O -Wno-format-security

CFLAGS_OPTIMIZED_32 = -DInPlace32BI -Wno-format-security -fomit-frame-pointer -O3 -g0 -march=native -mtune=native

CFLAGS_COMPACT = -DCompact -Wno-format-security -fomit-frame-pointer -O3 -g0 -march=native -mtune=native

CFLAGS_OPTIMIZED_64 = -DOptimized64 -Wno-format-security -fomit-frame-pointer -O3 -g0 -march=native -mtune=native

VPATH = Common/ Constructions/ KeccakF-1600/ KeccakF-1600/Optimized/ KeccakF-1600/Reference/ KeccakF-1600/Compact/ Modes/ Tests/

INCLUDES = -ICommon/ -IConstructions/ -IKeccakF-1600/ -IKeccakF-1600/Optimized/ -IKeccakF-1600/Reference/ -IModes/ -ITests/

$(BINDIR_REFERENCE)/%.o:%.c $(HEADERS_REFERENCE)
	$(CC) $(INCLUDES) $(CFLAGS_REFERENCE) -c $< -o $@

$(BINDIR_REFERENCE32BI)/%.o:%.c $(HEADERS_REFERENCE32BI)
	$(CC) $(INCLUDES) $(CFLAGS_REFERENCE32BI) -c $< -o $@

$(BINDIR_OPTIMIZED_64)/%.o:%.c $(HEADERS_OPTIMIZED_64)
	$(CC) $(INCLUDES) $(CFLAGS_OPTIMIZED_64) -c $< -o $@

$(BINDIR_INPLACE32BI)/%.o:%.c $(HEADERS_INPLACE32BI)
	$(CC) $(INCLUDES) $(CFLAGS_OPTIMIZED_32) -c $< -o $@

$(BINDIR_COMPACT)/%.o:%.c $(HEADERS_INPLACE32BI)
	$(CC) $(INCLUDES) $(CFLAGS_COMPACT) -c $< -o $@

.PHONY: sha3sumr64 sha3sumr32 sha3sum64 sha3sum32 sha3sumc

reference: bin/sha3sumr64 bin/sha3sumr32

optimized: bin/sha3sum64 bin/sha3sum32 bin/sha3sumc

32-bit: bin/sha3sum32 bin/sha3sumr32 bin/sha3sumc

64-bit: bin/sha3sum64 bin/sha3sumr64

sha3sumr64: bin/sha3sumr64

bin/sha3sumr64:  $(BINDIR_REFERENCE) $(OBJECTS_REFERENCE)  $(HEADERS_REFERENCE)
	$(CC) $(CFLAGS_REFERENCE) -o $@ $(OBJECTS_REFERENCE)

sha3sumr32: bin/sha3sumr32

bin/sha3sumr32:  $(BINDIR_REFERENCE32BI) $(OBJECTS_REFERENCE32BI)  $(HEADERS_REFERENCE32BI)
	$(CC) $(CFLAGS_REFERENCE32BI) -o $@ $(OBJECTS_REFERENCE32BI)

sha3sum64: bin/sha3sum64

bin/sha3sum64:  $(BINDIR_OPTIMIZED_64) $(OBJECTS_OPTIMIZED_64)  $(HEADERS_OPTIMIZED_64)
	$(CC) $(CFLAGS_OPTIMIZED_64) -o $@ $(OBJECTS_OPTIMIZED_64)

sha3sum32: bin/sha3sum32

bin/sha3sum32:  $(BINDIR_INPLACE32BI) $(OBJECTS_INPLACE32BI)  $(HEADERS_INPLACE32BI)
	$(CC) $(CFLAGS_INPLACE32BI) -o $@ $(OBJECTS_INPLACE32BI)

sha3sumc: bin/sha3sumc

bin/sha3sumc:  $(BINDIR_COMPACT) $(OBJECTS_COMPACT)  $(HEADERS_INPLACE32BI)
	$(CC) $(CFLAGS_COMPACT) -o $@ $(OBJECTS_COMPACT)

.PHONY: clean

clean:
	rm -rf bin/
