/* SPDX-License-Identifier: GPL-2.0-only AND GPL-CC-1.0 */
/*
 * Module: sha3sum.h     V1.x    Nov 2019         Jim McDevitt
 *
 * Copyright (c) 2012-2019 McDevitt Heavy Industries, Ltd. (MHI)
 *                   All Rights Reserved.
 *
 * This file is a part of sha3sum and is governed by the
 * GNU general public license Version 2.0 ONLY AND
 * the GPL Cooperation Commitment - GPL-CC-1.0; the full text
 * of which is contained in the file LICENSE included in all
 * binary and source code distribution packages.
 *
 */

#ifndef SHA3SUM_H_
#define SHA3SUM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Hash mode and duplex mode interface to the Keccak routines */
#include "KeccakHash.h"
#include "KeccakDuplex.h"
#include "sha3sum-config.h"

/*************************************************************************
**                            M A C R O S                               **
*************************************************************************/
/* Build Types */
#ifdef KeccakReference
	#define Reference
	const char class[] = "reference 64-bit";
#elif defined KeccakReference32BI
	#define Reference
	const char class[] = "reference 32-bit BI";
#elif defined InPlace32BI
	const char class[] = "optimized IP 32-bit BI";
#elif defined Optimized64
	const char class[] = "optimized 64-bit";
#elif defined Compact
	const char class[] = "compact 64-bit";
#else
	const char class[] = "undefined variant";
#endif

#ifdef __mingw__
	const char OS[] = "minGW";
#elif defined __linux__
	const char OS[] = "Linux";
#elif defined(_WIN32) || defined(_WIN64)
	const char OS[] = "Windows";
#else
	const char OS[] = "Unknown";
#endif

#if defined(__ICC) || defined(__ICL)
	const char CC[] = "Intel icc";
#elif __CLANG__
	const char CC[] = "Clang/LLVM";
#elif __GNUC__
	const char CC[] = "Gnu gcc";
#else
	const char CC[] = "unknown";
#endif

/* Macros */
#ifndef min
	#define min(a,b) ((a)<(b)? (a) : (b))
#endif

#ifndef max
	#define max(a,b) ((a)>(b)? (a) : (b))
#endif

#ifndef burn
	#define burn(a,b) ( memset((a), 0x00, (b)) )
#endif

/* length in bytes to use for disk I/O that is a multiple of (a) and is at least (b) bytes */
#ifndef SETHBL
	#define SETHBL(a,b) HBL = (a) / 8; HBL += (b) - (b) % HBL;
#endif

/*************************************************************************
**                         P R O T O T Y P E S                          **
*************************************************************************/

/* declare forward references and external routines */
static void optC(char *optstr);
static void optd(char *optstr);
static void optD(char *optstr);
static void opte(char *optstr);
static void optg(char *optstr);
static void optj(char *optstr);
static void optJ(char *optstr);
static void optk(char *optstr);
static void optK(char *optstr);
static void optL(char *optstr);
static void optm(char *optstr);
static void optM(char *optstr);
static void optn(char *optstr);
static void optr(char *optstr);
static void optx(int argc, char **argv, int i);
static void optX(int argc, char **argv, int i);
static void Save_settings();
#ifndef __mingw__
static void randombytes(unsigned char *x,unsigned long long xlen);
#endif
static void Restore_settings();
static int quick_hash(unsigned char *buffer, int size, unsigned int capacity, const int iterations);
static void check_line(char *line);
static int compute_hex_hashval();
static int ConvertDigitsToBytes(BitSequence* digits, BitSequence* bytes, int n);
static void hash_update(const BitSequence *data, DataLength databitlen);
static void duplexing(unsigned char *sigma, unsigned int sigmaBitLength,
						unsigned char *Z, const unsigned int ZByteLen);
static void print_config();
static void Print_Parameters();
#ifdef Reference
	static void optR(char *optstr);
	void displaySetIntermediateValueFile(FILE *f);
	void displaySetLevel(int level);
	void displayRoundConstants( FILE *outFile);
	void displayRhoOffsets( FILE *outFile);
	void displayStateAsBytes(int level, const char *text, const unsigned char *state);
#endif

/*************************************************************************
**                     K E C C A K   S T A T E S                        **
*************************************************************************/

Keccak_HashInstance hash;				/* Keccak hash instance */
Keccak_DuplexInstance duplex;
#ifdef Reference
	Keccak_SpongeInstance sponge;		/* Keccak sponge instance */
#endif

/*************************************************************************
**                           P R E S E T S                              **
*************************************************************************/

/* Keccak settings structure */
typedef struct config {
	unsigned int d;
	unsigned int C;
	BitSequence D;
	char desig[9];
	char tag[9];
	unsigned int R;
} Keccak;

Keccak settings[PRESETS];

/*************************************************************************
**                           G L O B A L S                              **
*************************************************************************/

BitSequence K[KEY_SIZE * 2 + 1];        /* ASCII or alpha hex string */
BitSequence binary_key[KEY_SIZE];       /* binary key (as entered) */
BitSequence IV[IV_SIZE * 2 + 1];        /* Initialization Vector (IV) (ASCII or hex) */
BitSequence binary_IV[IV_SIZE];         /* binary IV (as entered) */
BitSequence Msg[MSG_SIZE * 2 + 1];      /* message to be hashed (given with -M or -m) */
BitSequence hashval[MAXSIZE / 8];       /* message digest */
BitSequence hexhashval[MAXSIZE * 2 + 1];/* zero-terminated string representing hex value of hashval */
unsigned char key_data[KEY_FILE_SIZE];  /* binary key from specified file */
unsigned char IV_data[IV_FILE_SIZE];    /* binary IV from specified file */
unsigned char Duplex_out[WIDTH / 8];    /* accumulated output vector (duplex construct) */
unsigned char KeyFileSpec[FILESPEC_SIZE];      /* key file name used */
unsigned char IVFileSpec[FILESPEC_SIZE];       /* IV file name used */
unsigned char GenIVfile[MAXSIZE / 8];   /* If IV is generated, This is the filename of it */
char outfile[FILESPEC_SIZE];            /* Statistics output data file */
unsigned char rseed[SEEDSIZE / 8];      /* seed */
unsigned char binkey[MAXSIZE / 8];      /* processed key */
unsigned char binIV[MAXSIZE / 8];       /* processed IV */
unsigned int Key_bytes_used;            /* how many bytes used for the processed key */
unsigned int IV_bytes_used;             /* how many bytes used for the processed IV */

/* variables to save SOME settings */
unsigned int save_d;
unsigned int save_C;
BitSequence save_D;
unsigned int save_R;
int save_Lopt;
unsigned int save_squeezedOutputLength;
int save_MsgPresent;
uint64_t save_kb_count;
uint64_t save_Oopt;
uint64_t save_oopt;
int save_key_used;
int save_IV_used;
int save_lopt;
int save_pk;
int save_pp;
int save_pt;
int save_final;
int save_init;
int save_KP;
int save_IVP;

/*************************************************************************
**                        H E L P   T E X T                             **
*************************************************************************/

char help_part_1[] =
"usage: sha3sum [OPTIONS] file1 file2 ... [ [OPTIONS] file3 file4 ... ] ...\n"
"Options:\n"
"\t(option letters are case-sensitive and processed in order given):\n"
"\t-bn\tHash a dummy file of length n bits.\n"
"\t-Bn\tHash a dummy file of length n bytes.\n"
"\t-c xxxx\tCheck hash from file xxxx to see if they are still valid.\n"
"\t\tHere xxxx is saved output from a previous run of sha3sum.\n"
"\t\tNames of files whose hash value have changed are printed.\n"
"\t-Cn\tSet capacity to n (0<=n<=%d); default is %d.\n"
"\t\tAlso sets r (rate) to %d - C (capacity).\n"
"\t-dn\tSet digest length d to n bits, 8<=n<=r (rate);\n"
"\t\tdefault is %d. See also -Ln.\n"
"\t-Dxx\tSet delimited suffix to xx (hexadecimal), 01<=xx<=ff;\n"
"\t\tdefault is %02x (hex).\n"
"\t-en\tPrint n (optional) blocks of output -Ln bits in size.\n"
"\t\tUsed for arbitrary length output, n>0; default is 1.\n"
"\t\tIf this option is not present and -Ln is, -e1 assumed.\n"
"\t+/-f xxxx\n"
"\t\tOutput is to file; binary or ASCII hex. Used with -Ln\n"
"\t\tand -en. -f is in squeeze mode, +f is in duplex mode.\n"
"\t\tOutput is then generated from a key, key file,\n"
"\t\tIV, IV file, and/or a random seed.\n"
"\t-gn\tIf n (optional) = 0, a binary file is produced (default);\n"
"\t\tif n=1, an ASCII hex file is created. Used with -Ln and -f.\n"
"\t\tSee also option -en.\n"
"\t-h\tPrint this help information.\n"
#ifdef Reference
	"\t-in\tPrint level n intermediate values (n optional) 1<=n<=3;\n"
	"\t\tdefault is 1.\n"
#endif
"\t-jxxyy\tSet IV or salt to hexadecimal xxyy.. (length 1 to %d bits);\n"
"\t-Jxxxx\tSet IV or salt to ASCII xxxx (length 1 to %d bytes);\n"
"\t-kxxxx\tSet key to hexadecimal xxxx (length 0 to %d bits);\n"
"\t\txxxx optional.\n"
"\t-Kxxxx\tSet key to ASCII xxxx (length 0 to %d bytes);\n"
"\t\txxxx optional.\n"
"\t-ln\tUse n bits (0<=n<=%d) for the message size given with\n"
"\t\tthe -m option.\n"
"\t-Ln\tOutput n bits per squeeze (1<=n<=%d); default is %d.\n"
"\t\tArbitrary length output. See also option -e.\n"
"\t-mxxxx\tCompute hash of hexadecimal message xxxx;\n"
"\t\txxxx optional.\n"
"\t-Mxxxx\tCompute hash of ASCII message xxxx;\n"
"\t\txxxx optional.\n"
"\t-nc\tConfigures all settings based on capacity.\n"
"\t\tIf c is the capacity, then d = c/2, r = %d-c,\n"
"\t\tD = %02x (hex), s = c/2."
#ifdef Reference
	" R is set to %d.\n"
#else
	"\n"
#endif
"\t-Nn\tConfigures all settings based on the following table\n"
"\t\twhere n is the preset #, d is the digest size, r is the\n"
"\t\trate, C is the capacity, and D is the delimiter.\n"
#ifdef Reference
	"\t\tThe number of rounds (-R) is set to %d.\n"
#endif
"\n\t\t n   d    r    C   D  Designator Strength\n"
"\t\t=========================================\n"
;
char help_part_2[] =
"\t\t=========================================\n"
"\t\t VLO denotes variable length output.\n\n"
"\t-on\tSlow n-bit one-way function. Update state with\n"
"\t\tn 0 bits before the state is finalized.\n"
"\t-On\tSlow n-byte one-way function. Update state with\n"
"\t\tn 0 bytes before the state is finalized.\n"
"\t-p\tPrint input parameters.\n"
"\t+/-q infile outfile\n"
"\t\tStraight stream cipher. Apply key stream to file infile,\n"
"\t\tand write the result to file outfile. +q encrypts,\n"
"\t\t-q decrypts. A key and/or IV may be specified.\n"
"\t+/-Q infile outfile\n"
"\t\tStream cipher. Apply key stream to file infile,\n"
"\t\tand write the result to file outfile. +Q encrypts,\n"
"\t\t-Q decrypts. Unlike -q, this uses the duplex construct.\n"
"\t\tRequired input is a key. An IV may be specified.\n"
"\t\tThe stream is re-seeded every r/8 - 1 bytes.\n"
"\t\tIf no IV is specified, an IV will be generated.\n"
"\t-rn\tSet rate to n (16<=n<=%d); default is %d.\n"
"\t\tAlso sets C (capacity) to %d - r (rate).\n"
#ifdef Reference
	"\t-Rn\tSet rounds to n (1<=n<=%d); default is %d.\n"
#endif
"\t-sn\tMeasure time to perform n initializations (n optional)\n"
"\t\ton any provided configuration; n defaults to one.\n"
/* can be a hidden option if desired */
"\t-S\tAllow the key to be printed. This is used by options -c\n"
"\t\tand -p. Should only be used for testing purposes or if\n"
"\t\tthe key is used for non-security purposes such as a salt.\n"
"\t\tThe key printed is specified by -K.\n"
"\t-t\tTurn on printing of elapsed times and bytes/second\n"
"\t\tfor each hash as well as the job total.\n"
"\t-T\tTurn on printing of elapsed times and bytes/second\n"
"\t\tfor the job total only.\n"
"\t-u\tGenerate and use a random seed of %d bits. Useful\n"
"\t\tfor generating key files and IV files. Note that the use of\n"
"\t\tthis option renders any operation non-reproducible.\n"
"\t-v\tPrint program version information.\n"
"\t-x xxxx\tUse the first %d bytes of file xxxx as a key file.\n"
"\t\tIf -k or -K is also used, the key and this file are combined.\n"
"\t-X xxxx\tUse the first %d bytes of file xxxx as an IV file.\n"
"\t\tIf -j or -J is also used, the IV and this file are combined.\n"
"\t-yn\tPIM - Specify number key iterations (default = %d)\n"
"\t\tThe minimum is 10000.\n\n"
"For each file given, sha3sum prints a line of the form: \n"
"\thashvalue filename\n"
"If file is `-', or if no files are given, standard input is used.\n"
"Integers n may use scientific notation, e.g. -B1e9 .\n"
;

#endif /* SHA3SUM_H_ */
