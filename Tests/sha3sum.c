/* SPDX-License-Identifier: GPL-2.0-only AND GPL-CC-1.0 */
/*
 * Module: sha3sum.c     V1.x    Feb 2021         Jim McDevitt
 *
 * Copyright (c) 2012-2021 McDevitt Heavy Industries, Inc. (MHI)
 *                   All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * and its documentation for NON-COMMERCIAL and/or COMMERCIAL
 * purposes is hereby granted governed by the GNU general public
 * license Version 2.0 ONLY AND the GPL Cooperation Commitment-
 * GPL-CC-1.0; the full text of which is contained in the files
 * LICENSE and COMMITMENT, included in all binary and source
 * code distribution packages.
 *
 * MHI MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. MHI SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 *
 * IF THIS SOFTWARE IS FOR USE AS ON-LINE CONTROL EQUIPMENT
 * IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE PERFORMANCE, SUCH AS
 * IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR
 * COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE SUPPORT
 * MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
 * SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
 * PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"),  MHI
 * SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS
 * FOR HIGH RISK ACTIVITIES, WHETHER OR NOT MHI OR ITS SUBCONTRACTOR
 * WAS NEGLIGENT IN THE DESIGN, MANUFACTURE, OR WARNING OF THE MHI
 * PRODUCT OR ANY OF ITS PARTS.
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software
 * along with the GNU general public license Version 2.0 ONLY.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
 * Hash mode interface to the "Keccak Code Package."
 *
 * This program illustrates some different uses of the Keccak
 * hash primitive - or the SHA3 hash standard as provided in the
 * "Keccak Code Package" available at:
 *
 * http://keccak.noekeon.org
 *
 * Input can consist of (in binary or ASCII): a n-bit key, a n-bit IV,
 * a n-byte key file, a n-byte IV file, a n-bit message, an 8-bit
 * delimited suffix, a random seed, stdin, and/or any number of input files.
 * Output can be either binary (to a file), or ASCII hex (to a file
 * or stdout). Output files can be statistically analyzed or processed
 * accordingly for your purposes.
 *
 * Usually this program is linked with the optimized versions of the
 * Keccak routines as they are much faster; but for debugging or research
 * purposes, the "reference" versions of the Keccak routines are more
 * suitable. They are much slower, but the number of rounds can be specified
 * as well as the printing of intermediate values. If this functionality
 * is not needed, the optimized versions should be used.
 *
 * I have incorporated special versions of the Keccak hash function and the
 * stream cipher, into the Truecrypt(r) program. There is also a version of
 * Keccak extensively optimized and parallelized for the Intel(r) MIC
 * architecture (one of the reasons I wrote this program). Tree hashing
 * benefits extensively from this. The version of Keccak used here is that
 * from the code package.
 *
 * Installation and documentation are provided in the files INSTALL and
 * README respectively.
 *
 */

/* A portion of this product is based in part on md6sum.
 * Copyright (c) 2008 Ronald L. Rivest
 */

#include "sha3sum.h"

/*************************************************************************
**         K E C C A K   O P E R A T I N G   P A R A M E T E R S        **
*************************************************************************/

unsigned int d = DEFAULT_D;                   /* digest length (bits) */
unsigned int r = DEFAULT_R;                   /* rate (bits) */
unsigned int C = DEFAULT_C;                   /* capacity (bits) */
unsigned int nrRounds = DEFAULT_ROUNDS;       /* number of rounds
											   * need to use the "reference" version
											   * of the Keccak routines. */
unsigned int squeezedOutputLength = DEFAULT_SQUEEZE;   /* number of bits produced per squeeze */
BitSequence delimitedSuffix = DEFAULT_DELIMITER;       /* delimited suffix:
											   * Bits that will be automatically appended to the end
											   * of the input message, as in domain separation,
											   * a delimiter, or a diversifier ??
											   * This is a byte containing from 0 to 7 bits
											   * formatted like the @a delimitedData parameter of
											   * the Keccak_SpongeAbsorbLastFewBits() function.
											   * 0x01 means not to absorb any extra bits. */

/*************************************************************************
**                     M I S C   R O U T I N E S                        **
*************************************************************************/

static uint64_t get_int(char *s) {
/* return integer starting at s (input presumed to end with '\n')
** (It may be expressed in exponential format e.g. 1e9.)
*/
#ifdef __mingw__
	double g = 0;
	g = strtod(s, NULL);
#else
	long double g = 0;
	sscanf(s, "%Lg", &g);
#endif
	return ((uint64_t)g);
}

/* routines to escape/un-escape filenames, in case they
** contain backslash or \n 's.
*/
static void encode(char *s, char *t) {
/* input t, output s -- recode t so it all newlines and
** backslashes are escaped as \n and \\ respectively.
** Also, a leading '-' is escaped to \-.
*/
	if (*t && *t == '-') {
		*s++ = '\\'; *s++ = '-'; t++; }
	while (*t) {
		if (*t == '\\')         { *s++ = '\\'; *s++ = '\\'; }
		else if (*t == '\n')    { *s++ = '\\'; *s++ = 'n';  }
		else                    *s++ = *t;
		t++;
	}
	*s = 0;
	return;
}

static void decode(char *s, char *t) {
/* inverse of encode -- s is un-escaped version of t. */
	while (*t) {
		if (*t == '\\') {
			if (*(t + 1) == '\\')       { *s++ = '\\'; t += 1; }
			else if (*(t + 1) == 'n')   { *s++ = '\n'; t += 1; }
			else if (*(t + 1) == '-')   { *s++ = '-'; t += 1; }
			else if (*(t + 1) == 0)     { *s++ = '\\'; }
			else                        { *s++ = *t; }
		}
		else *s++ = *t;
		t++;
	}
	*s = 0;
	return;
}

static void Security_strength (unsigned int d, unsigned int C, char *tag, unsigned int *s, char *sl ) {
/* determine security strength given the capacity, digest size, and if VLO or not (tag)
 */
	burn (sl, 16);
	*s = d / 2;

	if ( strcmp(tag, "VLO") == 0 ) {    /* if VLO, s <= C/2 */
		strncpy (sl, "s <= ", 5);
		*s = C / 2;
	}
	else                                /* else s >= d/2 */
		strncpy (sl, "s >= ", 5);
}

static void PrintBuffer(unsigned char *buffer, int size) {
/* print specified buffer in hex */
	int l=0;

	do {
		printf("%02x", buffer[l++]);
	} while (l < size);
	printf("\n");
}

static void Process_Key( unsigned int *bytes_used ) {
/* Process key and keyfile */
	int i;
	*bytes_used = 0;
	Update_error = 0;

	burn (binkey, MAXSIZE / 8);

	if ( xopt ) {											/* if a key file used */
		for (i = 0; i < KEY_FILE_SIZE; i++)					/*   copy key file to the buffer */
			binkey[i] = key_data[i];
		if ( key_used ) {									/*   if also a key from CLI */
			for (i = 0; i < KEY_SIZE; i++)
				binkey[i] ^= binary_key[i];					/*     then add the key */
			*bytes_used = max (KEY_FILE_SIZE, KEY_SIZE);	/*     save the size of key + key file */
		}
		else												/*   otherwise */
			*bytes_used = KEY_FILE_SIZE;					/*     save the size of the key file */
	}
	else {													/* otherwise */
		if ( key_used ) {									/* if just the key used */
			*bytes_used = KEY_SIZE;							/*   save the size of the key */
			for (i = 0; i < KEY_SIZE; i++)					/*   add key to the buffer */
				binkey[i] = binary_key[i];
		}
	}

	if ( !sopt ) {	/* Don't clear key material if called from -s option */
		/* bag all original key material */
		burn (key_data, sizeof(key_data));
		burn (binary_key, sizeof(binary_key));
		if ( !print_key_ok )		/* bag only if -S not used (hidden option) */
			burn (K, sizeof(K));
	}

	/* slow one-way hash entire buffer even if no key */
	Update_error = quick_hash (binkey, MAXSIZE / 8, 1024, pim, QH_KY);

	if ( Update_error ) {
		*bytes_used = 0;
		burn (binkey, MAXSIZE / 8);
		printf("--F - Error in key computation; error code %d.", Update_error);
		return;
	}

	/* flag it processed if no error regardless if there was a key or not */
	Key_processed = 1;
}

static void Process_IV( unsigned int *bytes_used ) {
/* process IV and IV file */
	unsigned int i;
	*bytes_used = 0;

	burn (binIV, MAXSIZE / 8);

	/* Key must be processed first */
	if ( !Key_processed ) {
		Update_error = 111;
		goto error;
	}

	if ( Xopt ) {										/* if an IV file used */
		for (i = 0; i < sizeof(IV_data); i++)
			binIV[i] = IV_data[i];						/*   copy the IV file to the buffer */
		if ( IV_used ) {								/*   if also an IV from the CLI */
			for (i = 0; i < IVlen; i++)
				binIV[i] ^= binary_IV[i];				/*     add the IV to the IV file */
			*bytes_used =  max(IV_FILE_SIZE, IVlen);	/*     save the size of IV + IV file */
			for (i = 0; i < MAXSIZE / 8; i++)			/*     update the buffer with the IV AND */
				binIV[i] ^= ~binkey[i];					/*     the complement of the KEY */	
		}
		else											/*   otherwise */
			*bytes_used = IV_FILE_SIZE;					/*     save the size of the IV file */
	}
	else {												/* otherwise */
		if ( IV_used ) {                             	/*   if just the IV only */
			*bytes_used = IVlen;						/*     save the size of the IV */
			for (i = 0; i < IVlen; i++)					/*     update the buffer with the IV */
				binIV[i] = binary_IV[i];
			for (i = 0; i < MAXSIZE / 8; i++)			/*     and combine with the */
				binIV[i] ^= ~binkey[i];					/*     complement of the key */
		}
	}

	/* hash the ENTIRE buffer even if no IV */
	Update_error = quick_hash (binIV, MAXSIZE / 8, 1024, 2, QH_IV);

error:

	if ( Update_error ) {
		burn (IV_data, sizeof(IV_data));
		burn (binary_IV, sizeof(binary_IV));
		*bytes_used = 0;
		burn (binIV, MAXSIZE / 8);
		printf("--F - Error in IV computation; error code %d.", Update_error);
		return;
	}

	IV_processed = 1;	/* flag it processed if there was a IV or not */
}

/*************************************************************************
**      T I M I N G   V A R I A B L E S   &   R O U T I N E S           **
*************************************************************************/

/* Cycle count routines */
#if defined (_MSC_VER)

	/* Microsoft */
	#include <intrin.h>
	#pragma intrinsic(__rdtsc)
	uint64_t ticks() {
		return (__rdtsc());
	}
	#define ROL64(a, offset) _rotl64(a, offset)

#elif defined(__INTEL_COMPILER)

	/* Intel */
	inline uint64_t ticks() {
		return ((uint64_t)__rdtsc());
	}
	#define ROL64(a, offset) _lrotl(a, offset)

#else

	/* GCC */
	/* read timestamp counter */
	#include <stdint.h>
	inline uint64_t ticks() {
		uint32_t lo, hi;
		asm volatile (
			"xorl %%eax,%%eax \n        cpuid"
			::: "%rax", "%rbx", "%rcx", "%rdx");
		asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
		return ((uint64_t)hi << 32 | lo);
	}
	#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))

#endif

int tod_printed = 0;
static void print_tod() {
/* print time-of-day if it hasn't been printed yet. */
	time_t now;
	if ( !tod_printed && !copt ) { /* do not print if already printed or we are in optc() */
		time(&now);
		printf("-- %s",ctime(&now));
		tod_printed = 1;
	}
}

double start_time, job_start_time;
double end_time, job_end_time;
uint64_t start_ticks, end_ticks;
double job_elapsed_time = 0.0;
uint64_t job_elapsed_ticks = 0;
double elapsed_time = 0;
uint64_t elapsed_ticks = 0;

/* accumulate timing data */
static void add_time() {
	elapsed_time = end_time - start_time;
	elapsed_ticks = end_ticks - start_ticks;
	job_elapsed_time += elapsed_time;
	job_elapsed_ticks += elapsed_ticks;
}

/* start the timer */
static void start_timer() {
	start_time = ((double)clock()) / CLOCKS_PER_SEC;
	start_ticks = ticks();
}

/* stop the timer and add the interval */
static void end_timer() {
	end_time = ((double)clock()) / CLOCKS_PER_SEC;
	end_ticks = ticks();
	add_time();
}

/* For the entire run */
static void job_start_timer() {
	job_start_time = ((double)clock()) / CLOCKS_PER_SEC;
}
static void job_end_timer() {
	job_end_time = ((double)clock()) / CLOCKS_PER_SEC;
}

static void init_counters_flags() {
/* reset global counters, state flags
* and errors
* called before each hash is computed
* at the beginning of hash_init() */
	bits_processed = bits_squeezed = absorb_calls = squeeze_calls = 0;
	Initialized = Finalized = Update_error = file_error = 0;
}

int print_times = 0;
int times_printed = 0;

static void print_time() {
	/* if end of job */
	if ( eoj ) {
		elapsed_time = job_elapsed_time;
		elapsed_ticks = job_elapsed_ticks;
	}
	long long int tb = 0;
	long long int ts = 0;
	uint64_t bytes = bits_processed >> 3;
	int bits = bits_processed % 8;
	uint64_t sqbytes = bits_squeezed >> 3;
	int sqbits = bits_squeezed % 8;

	if ( print_times == 0 || !Finalized )
		return;
	if ( print_times == 1 && !eoj )
		return;

	if ( bits_processed ) {
		printf("-- Length in = ");
		if (bits_processed==0) printf("0");
		if (bytes > 0) printf("%g byte", (double)bytes);
		if (bytes > 1) printf("s");
		if (bytes > 0 && bits > 0) printf(" + ");
		if (bits > 0) printf("%d bit", bits);
		if (bits > 1) printf("s");
		printf("\n");
	}

	if ( bits_squeezed ) {
		printf("-- Length out = ");
		if (bits_squeezed == 0) printf("0");
		if (sqbytes > 0) printf("%g byte", (double)sqbytes);
		if (sqbytes > 1) printf("s");
		if (sqbytes > 0 && sqbits > 0) printf(" + ");
		if (sqbits > 0) printf("%d bit", sqbits);
		if (sqbits > 1) printf("s");
		printf("\n");
	}

	if (elapsed_time <= 0.0) {
		printf("-- Elapsed time too short to measure...\n");
		if (absorb_calls )
			printf("-- Absorption calls made = %lld\n", absorb_calls);
		if ( squeeze_calls )
			printf("-- Squeeze calls made = %lld\n", squeeze_calls);
	}
	else {
		if (elapsed_time >= (double)0.0)
			printf("-- Elapsed time = %.3f seconds\n", elapsed_time);
		else
			printf("-- Elapsed time = ** Too short to measure **\n");

		if (absorb_calls) {
			printf("-- Absorption calls made = %lld\n", absorb_calls);
			if ( (bytes / elapsed_time / 1000000.0) > 1.0 ) {
				printf("-- Megabytes absorbed per second = %g\n",
						(bytes/elapsed_time) / 1000000.0);
				printf("-- Microseconds per absorption = %g\n",
						(elapsed_time * 1.0e6 / absorb_calls ));
			}
		}
		if ( squeeze_calls ) {
			printf("-- Squeeze calls made = %lld\n", squeeze_calls);
			if ( (sqbytes / elapsed_time / 1000000.0) > 1.0 ) {
				printf("-- Megabytes squeezed per second = %g\n",
						(sqbytes / elapsed_time) / 1000000.0);
				printf("-- Microseconds per squeeze = %g\n",
						(elapsed_time * 1.0e6 / squeeze_calls ));
			}
		}
	}

	printf("-- Total clock ticks = %lld\n", (long long int)elapsed_ticks);

	if (bytes > 0) {
		tb = (long long int)elapsed_ticks/bytes;
		ts = (long long int)elapsed_ticks/absorb_calls;
		if ( tb == 0 )
			printf("-- Clock ticks / byte absorbed is too short to measure...\n");
		else
			if ( tb < 2000 ) {	/* not applicable if too large */
				printf("-- Clock ticks / byte absorbed = %lld\n", tb);
				if ( ts == 0 )
					printf("-- Clock ticks / absorbtion call is too short to measure...\n");
				else
					printf("-- Clock ticks / absorption call = %lld\n", ts);
			}
	}

	if ( sqbytes > 0 ) {
		tb = (long long int)(elapsed_ticks / sqbytes);
		ts = (long long int)(elapsed_ticks / squeeze_calls);
		if ( tb == 0 )
			printf("-- Clock ticks / byte squeezed is too short to measure...\n");
		else
			if ( tb < 2000 ) {	/* not applicable if too large */
				printf("-- Clock ticks / byte squeezed = %lld\n", tb);
				if ( ts == 0 )
					printf("-- Clock ticks / squeeze call is too short to measure...\n");
				else
					printf("-- Clock ticks / squeeze call = %lld\n", ts);
			}
	}

	printf("\n");
	times_printed++;
}

/*************************************************************************
**         K E C C A K   H A S H   M O D E   I N T E R F A C E          **
*************************************************************************/

static void hash_init() {
/* initialize state */
	int err;

	/* check parameters for saneness */
	if ( MsgPresent == 0 && lopt ) {   /* bit length specified (-l) but no message (-m) */
		lopt = 0;
		printf("--W - Option -l%d ignored; missing option -m.\n", mBitLength);
	}

	if ( kb_count > 1 && !Lopt ) {   /* -e was specified but the switch -Ln was not */
		printf("--W - Option -e%lld ignored; missing option -Ln.\n", kb_count);
		kb_count = 1;
	}

	if ( !Lopt && d > r ) {
		printf("--I - Changed digest size from %d to %d so 8<=digest<=%d.\n", d, r, r);
		d = r;
	}

	/* initialize counters and start the clock
	 * if not doing time trials */
	if ( trials == 0 ) {
		init_counters_flags();
		start_timer();	/* start the clock here */
	}

	/* Process key and key file if needed..
	 * Key and key file sizes are of fixed size and zero padded. */
	if ( Key_processed == 0 ) Process_Key( &Key_bytes_used );
	if ( Update_error ) return;

	/* Process IV and IV file if needed.
	 * IV and IV files are of fixed size and zero padded. */
	if ( IV_processed == 0 ) Process_IV( &IV_bytes_used );
	if ( Update_error ) return;

	/* initialize the hash */
	print_tod();
	if ( Lopt ) d = 0;					/* set digest size to zero if -L */
	err=Keccak_HashInitialize(&hash, r, C, d, delimitedSuffix);
	if ( err ) {
		printf("--F - Error: bad configuration parameters; can't initialize. "
				"error code = %d\n", err);
		return;
	}

#ifdef Reference
	/* If intermediate values are desired, and
	 * if they specified -i2, print the round constants
	 * and the rho offsets */
	if (print_intermediates && Update_error == 0) {
		if (level >= 2) {
			fprintf(outFile, "+++ The round constants +++\n");
			fprintf(outFile, "\n");
			displayRoundConstants(outFile);

			fprintf(outFile, "+++ The rho offsets +++\n");
			fprintf(outFile, "\n");
			displayRhoOffsets(outFile);
		}

		displayStateAsBytes(level, "Initial state", sponge.state);
	}
#endif

	/* that went well */
	Initialized = 1;

	/* If sponge initialized with d = 0, squeeze mode is desired,
	 * reset the digest. */
	if ( Lopt )
		d = squeezedOutputLength;

	/* Use the random seed if one was generated. */
	if ( seed_used && !Encoding )
		hash_update( rseed, (DataLength) SEEDSIZE );

	/* update with the key */
	if ( Key_bytes_used && Update_error == 0 )
		hash_update (binkey, (DataLength) MAXSIZE / 8 );

	/* update with the IV */
	if ( IV_bytes_used && Update_error == 0 )
		hash_update (binIV, (DataLength) MAXSIZE / 8 );

	/* flag initialization success or failure */
	if ( Update_error ) {
		Initialized = 0;
		printf("--F - Error: Initialization sequence or condition error.\n");
	}
}

static void hash_update(const BitSequence *data, DataLength databitlen) {
/* update the state */
	if ( Initialized && !Finalized && Update_error == 0 && databitlen > 0 ) {
		Update_error = Keccak_HashUpdate(&hash, data, databitlen);
		if (Update_error) {
			printf("--F - Update error. Error code: %d\n", Update_error);
			return;
		}

		bits_processed += databitlen;
		absorb_calls++;
		job_bits_processed += databitlen;
		job_absorb_calls++;
	}
	else
		printf("--F - Error: Update sequence or condition error.\n");
}

static void hash_final() {
/* finalize the state
 */
	int err;
	uint64_t nbytes, part_len;

	/* make sure it's OK to be here. If so; */
	if ( Initialized && !Finalized && Update_error == 0 ) {

		/* if -o or -O used, append the requested number
		 * of zero bits or bytes. Useful to determine how many
		 * bits or bytes desired for zero padding.
		 * nbytes is the number of zero bytes we need to pad the
		 * message by. This affects a slowdown as well. */
		if (oopt || Oopt) {
			if (oopt)
				nbytes = oopt / 8;
			else
				nbytes = Oopt;

			/* create a zero filled buffer of HBL bytes */
			SETHBL(r, DISK_BLOCK_SIZE)
			BitSequence *zeros = (BitSequence *) calloc( HBL, sizeof(BitSequence) );
			if (zeros == NULL) {
				printf("--F - Error: one-way function memory pool exhausted.\n");
				return;
			}

			/* feed the sponge */
			while ( nbytes > 0 && Update_error == 0 ) {
				part_len = min(HBL, nbytes);
				hash_update( zeros, (DataLength) (part_len << 3) );
				nbytes -= part_len;
			}
			free( zeros );
		}

		/* Finalize the hash */
		if ( Update_error == 0 ) {
			err = Keccak_HashFinal(&hash, hashval);
			end_timer();   /* stop the clock */
			if (err) {
				printf("--F - Error: finalization error. Error code: %d\n",err);
				return;
			}

			if ( !Lopt ) {
				if ( compute_hex_hashval() ) {
					printf("--F - Error: finalization error. NULL hash value or bad hex digit.\n");
					return;
				}
				bits_squeezed += d;
				job_bits_squeezed += d;
				squeeze_calls++;
				job_squeeze_calls++;
			}

			/* success */
			Finalized = 1;
		}
	}
	else
		printf("--F - Error: Finalization sequence or condition error.\n");
}

static mode hash_squeeze() {
/* Sponge squeeze mode. Arbitrary length output.
* can only be used after HashInit() and HashFinal().
* Hash_Init() must have been initialized with d = 0
* and used with option -Ln where n is the desired length.
* Each squeeze will produce n (squeezedOutputLength)
* bits. Squeeze as much as you like. Just like Charmin.
*/
	mode err;

	if (Finalized && Initialized && Update_error == 0) {
		err = (mode)Keccak_HashSqueeze(&hash, hashval, (DataLength)squeezedOutputLength);
		if (err)
			return (err);
		else {
			bits_squeezed += squeezedOutputLength;
			job_bits_squeezed += squeezedOutputLength;
			squeeze_calls++;
			job_squeeze_calls++;
			return (Success);
		}
	}
	printf("--F - Error: Squeeze mode sequence or condition error.\n");
	return (Fail);
}

static int quick_hash(unsigned char *buffer, int size, unsigned int capacity, const int iterations, const BitSequence delim) {
	/* do a quick hash on the supplied buffer. the buffer is then updated with the hash. */
	int err, i;
	int iter = 1;
	Save_settings(); /* save settings */

	/* configure with new parameters */
	Initialized = 0;
	Finalized = 0;
	d = 0;
	C = capacity;
	r = WIDTH - C;
	nrRounds = DEFAULT_ROUNDS;

	/* ensure domain separation for this hash
	 * enforced in config and optD() */
	delimitedSuffix = delim;

	/* set the output buffer length */
	squeezedOutputLength = MAXSIZE;

	/* initialize the state and set up for squeeze mode */
	if ( err = Keccak_HashInitialize(&hash, r, C, d, delimitedSuffix) ) {
		Restore_settings();
		return (err + 100);
	}

#ifdef Reference
	/* If intermediate values are desired, and
	 * if they specified -i2, print the round constants
	 * and the rho offsets */
	if (print_intermediates && Update_error == 0) {
		if (level >= 2) {
			fprintf(outFile, "+++ The round constants +++\n");
			fprintf(outFile, "\n");
			displayRoundConstants(outFile);

			fprintf(outFile, "+++ The rho offsets +++\n");
			fprintf(outFile, "\n");
			displayRhoOffsets(outFile);
		}

		displayStateAsBytes(level, "Initial state", sponge.state);
	}
#endif

	d = squeezedOutputLength;	/* set digest size to the squeeze size */
	Initialized = 1;

	/* load the buffer */
	hash_update (buffer, (DataLength) (size));

	/* return if any error */
	if ( Update_error ) {
		Restore_settings();
		return (Update_error + 300);
	}

	/* Finalize the hash */
	if ( err = Keccak_HashFinal(&hash, hashval) ) {
		Restore_settings();
		return (err + 400);
	}
	Finalized = 1;

	/* Get the hash of the buffer */
	for (i = 0; i < iter; i++) {
		hash_squeeze();
		if ( Update_error ) {
			Restore_settings();
			return (err + 500);
		}
	}

	/* set the ASCII hex string from the squeeze */
	if ( Update_error = compute_hex_hashval() ) {
		Restore_settings();
		return (err + 600);
	}

	/* copy the hash value to the buffer */
	burn(buffer, sizeof(buffer));
	memcpy(buffer, hashval, size);
	Restore_settings();
	return (Success);
}

/*************************************************************************
**   K E C C A K   D U P L E X   C O N S T R U C T   I N T E R F A C E  **
*************************************************************************/

static void Duplex_Queue( unsigned char *buffer, unsigned int size, unsigned char *stream ) {
/* feed the sponge r-8 bits at a go */
	unsigned int i;
	unsigned int datalen = size * 8;
	unsigned int offset = 0;

	if ( Update_error == 0 ) {
		while ( datalen && Update_error == 0 ) {
			i = min (datalen, (r - 8));
			duplexing(buffer + offset, i, stream, (unsigned int) (i >> 3));
			datalen -= i;
			offset += i / 8;
		}
	}
	if ( Update_error )
		printf("--F - Error: Duplex queue sequence or condition error.\n");
}

static void duplex_init() {
/* initialize duplex state */
	unsigned char bit_bucket[WIDTH / 8];
	unsigned int err;
	init_counters_flags();

	/* Process key(s) if any. */
	if ( Key_processed == 0 ) Process_Key ( &Key_bytes_used );
	if ( Update_error ) return;

	/* Process IV(s) if any. */
	if ( IV_processed == 0 ) Process_IV ( &IV_bytes_used );
	if ( Update_error ) return;

	/* do the initialization */
	err = Keccak_DuplexInitialize(&duplex, r, C);   /* initialize duplex instance */
	if ( err ) {
		printf("--F - Error: bad duplex configuration parameters; can't initialize. "
				"error code = %d\n", err);
		return;
	}

#ifdef Reference
	/* If intermediate values are desired,
	 * and this is the reference version;
	 * if they specified -i2, print them out.
	 */
	if (print_intermediates && Update_error == 0) {
		if ( level >= 2 ) {
			fprintf(outFile, "+++ The round constants +++\n");
			fprintf(outFile, "\n");
			displayRoundConstants(outFile);

			fprintf(outFile, "+++ The rho offsets +++\n");
			fprintf(outFile, "\n");
			displayRhoOffsets(outFile);
		}

		displayStateAsBytes(level, "Initial state", sponge.state);
	}
#endif

	Initialized = 1;	/* that went OK */
	print_tod();

	/* zero accumulator */
	burn (Duplex_out, WIDTH / 8);

	/* Use the seed if one was generated.
	 * This is primarily used for
	 * testing purposes. */
	if ( seed_used && !Encoding )
		Duplex_Queue (rseed, (unsigned int) (SEEDSIZE >> 3), bit_bucket);

	/* Update state with key(s) if any. */
	if ( Update_error == 0 && Key_bytes_used )
		Duplex_Queue(binkey, MAXSIZE / 8, bit_bucket);

	/* Update state with IV(s) if any. */
	if ( Update_error == 0 && IV_bytes_used )
		Duplex_Queue(binIV, MAXSIZE / 8, bit_bucket);

	if ( Update_error )
		Initialized = 0;	/* problem */
}

static void duplexing(unsigned char *sigma, unsigned int sigmaBitLength,
						unsigned char *Z, const unsigned int ZByteLen) {
	unsigned int i;
	unsigned int sigmaByteLenCeiling = (sigmaBitLength + 7) / 8;
	unsigned char delimitedSigmaEnd;
	unsigned char filler = 0xAA + sigmaBitLength;

	/* make sure we are allowed to be here */
	if ( !Initialized || Update_error ) {
		printf("--F - Error: Duplexing sequence or condition error.\n");
		return;
	}

	/* determine delimiter */
	if ((sigmaBitLength % 8) != 0) {
		sigma[sigmaByteLenCeiling - 1 ] &= (1 << (sigmaBitLength % 8)) - 1;
		delimitedSigmaEnd = sigma[sigmaByteLenCeiling - 1] | (1 << (sigmaBitLength % 8));
	}
	else
		delimitedSigmaEnd = NO_SUFFIX;

	memset(Z, filler, sizeof(Z));

	Update_error = Keccak_Duplexing(&duplex, sigma, sigmaBitLength>>3, Z, ZByteLen, delimitedSigmaEnd);
	if ( Update_error ) {
		printf("--F - Error: Duplexing error code: %d\n", Update_error);
		return;
	}

	/* accumulate the output */
	for(i = 0; i < ZByteLen; i++)
		Duplex_out[i] ^= Z[i];

	/* Integrity check for out of bounds data (over-write) */
	for(i = ZByteLen; i < sizeof(Z); i++)
		if (Z[i] != filler) {
			printf("--F - Internal error: Duplexing out of range data written.\n");
			Update_error = Fatal;
			return;
		}

	/* count bits in */
	if (sigmaBitLength) {
		bits_processed += sigmaBitLength;
		absorb_calls++;
		job_bits_processed += sigmaBitLength;
		job_absorb_calls++;
	}

	/* count bits out */
	if ( ZByteLen ) {
		bits_squeezed += ZByteLen<<3;
		job_bits_squeezed += ZByteLen<<3;
		squeeze_calls++;
		job_squeeze_calls++;
	}
}

/*************************************************************************
 ** routines to hash a file (or dummy file) or from stdin               **
 ************************************************************************/

static void hash_filep(FILE *inFile) {
/* read the file and feed the sponge */
	uint64_t bytes;

	if (inFile==NULL) {
		printf("--F - Error: hash_filep has NULL input file pointer.\n");
		return;
	}

	print_tod();
	hash_init();

	if ( Initialized ) {
		/* length in bytes of data to read that is a multiple of rate and is at least DISK_BLOCK_SIZE */
		SETHBL(r, DISK_BLOCK_SIZE)
		BitSequence *data = (BitSequence *) calloc( HBL, sizeof(BitSequence) );
		if (data == NULL) {
			printf("--F - Error: hash_filep memory pool exhausted.\n");
			return;
		}

		while ( (bytes = fread (data, 1, HBL, inFile)) != 0 && (Update_error == 0) )
			hash_update(data, (DataLength) (bytes << 3));
		hash_final();
		free (data);
	}
}

static void hash_stdin() {
/* hashes data from stdin */
	hash_filep(stdin);
}

static void hash_file( char *filename ) {
/* try to open the file. If ok then hash it */
	FILE *inFile = fopen (filename, "rb");
	if ( inFile == NULL ) {
		printf("--W - cannot open '%s'; ignored\n", filename);
		file_error = 1;
	}
	else {
		hash_filep(inFile);
		fclose(inFile);
	}
}

static void hash_b(uint64_t bitlen) {
/* Hash dummy input file of length bitlen bits.
** File (hex) repeats with period 8:
**   11 22 33 44 55 66 77 88 11 22 33 44 55 66 77 88 11 22 33 ...
*/
	int i;

	print_tod();
	/* length in bytes of data to read that is a multiple of rate and is at least DISK_BLOCK_SIZE */
	SETHBL(r, DISK_BLOCK_SIZE)
	BitSequence *data = (BitSequence *) calloc( HBL, sizeof(BitSequence) );
	if (data == NULL) {
		printf("--F - Error: hash_b memory pool exhausted.\n");
		return;
	}

	for ( i = 0; i < HBL; i++)
		data[i] =  0x11 + (char)((i % 8) * (0x11));
	hash_init();
	while ( bitlen > 0 && Update_error == 0 ) {
		uint64_t part_len = min(HBL << 3, bitlen);
		hash_update(data, (DataLength) part_len);
		bitlen = bitlen - part_len;
	}
	hash_final();
	free(data);
}

/*************************************************************************
**             C O M M A N D   L I N E   O P T I O N S                  **
*************************************************************************/

static void optb(char *optstr) {
/* -bnnnn hash dummy file of length nnnn bits */
	uint64_t bitlen = strlen(optstr) > 2 ? get_int(optstr + 2) : 0;
	if ( bitlen )
		hash_b(bitlen);
	else
		printf("--W - Illegal option %s ignored; no bits specified.\n", optstr);
}

static void optB(char *optstr) {
/* -Bnnnn hash dummy file of length nnnn bytes */
	uint64_t B = strlen(optstr) > 2 ? get_int(optstr + 2) : 0;
	if ( B )
		hash_b(B << 3);
	else
		printf("--W - Illegal option %s ignored; no bytes specified.\n", optstr);
}

static void optc(int argc, char **argv, int i) {
/* Recompute hashes, and check them for current validity.
** -c file     causes hashes from given file to be checked.
**             (This file is the output from a previous run of sha3sum.)
**             Only the names of files that's do not hash the same are printed.
*/
	FILE *checkfilep;
	char line[2 * FILESPEC_SIZE];
	if (i == (argc - 1)) {
		printf("--F - Error: no file given for -c option.\n");
		return;
	}
	checkfilep = fopen(argv[i + 1], "r");
	if (checkfilep == NULL) {
		printf("--F - Hash check file %s can't be opened.\n", argv[i + 1]);
		return;
	}

	/* Flag used to suppress time of day from printing.
	 * since the output from this option might be piped
	 * to another program, the only info that will print
	 * will be the filenames that fail verification.
	 */
	copt = 1;

	while (fgets( line, FILESPEC_SIZE - 3, checkfilep)) {
		if (strlen(line) == 0) continue;       /* empty string? */
		line[strlen(line) - 1] = 0;            /* kill '\n'     */
		if (strlen(line) == 0) continue;       /* empty now?    */
		if (line[0] == '-') {                  /* handle option */
			if (strlen(line) == 1)
				printf("--W - Hash check file contains illegal line with single '-'; ignored.\n");
			switch ( line[1] ) {
			case 'C': optC(line); break;		/* capacity */
			case 'd': optd(line); break;		/* digest size (bits) */
			case 'D': optD(line); break;		/* default delimiter */
			case 'e': opte(line); break;		/* number of -Ln size instances to output */
			case 'j': optj(line); break;		/* IV hex */
			case 'J': optJ(line); break;		/* IV ASCII */
			case 'k': optk(line); break;		/* hex key */
			case 'K': optK(line); break;		/* ASCII key */
			case 'L': optL(line); break;		/* bits output per squeeze */
			case 'r': optr(line); break;		/* bit rate */
#ifdef Reference
			case 'R': optR(line); break;		/* number of rounds */
#endif
			case ' ': break;					/* ignore lines starting with '- ' or '--' */
			case '-': break;
			default: printf("--W - Unrecognized option in check file: %s; ignored.\n", argv[i]);
			break;
			}
			continue;
		}
		/* now handle typical line with hash value */
		check_line(line);
	}
	fclose(checkfilep);
	copt = 0;   /* so print_tod() will print again if asked */
}

static void optC(char *optstr) {
/* set Keccak capacity
 * -Cn where 0<=n<=WIDTH-16
 * set rate to match this Capacity
 */
	unsigned int t;
	unsigned int Copt = get_int(optstr+2);

	C = Copt;
	if ( C > (WIDTH - 16) ) C = WIDTH - 16;
	t = C % 8;

	/* if we have to change C, try to raise it first. If out of range, then lower it. */
	if ( t ) {
		if (C + 8 - t > WIDTH - 16)
			C -= t;
		else
			C += 8 - t;
	}
	r = WIDTH - C;
	if ( Copt != C ) {
		printf( "--I - Changed capacity from %d to %d so 0<=C<=%d and divisible by 8; rate = %d.\n", Copt, C, WIDTH - 16, r );
	}
}

static void optd(char *optstr) {
/* set Keccak digest length
 * -dn sets digest length to n, 8 <= n <= rate (bits)
 */
	int t;
	int dopt = get_int(optstr + 2);
	if ( dopt == 0 ) dopt = DEFAULT_D;
	d = dopt;

	if ( d < 8 ) d = 8;
	if ( d > r ) d = r;
	t = d % 8;

	if ( t ) {
		if ( (d + 8 - t) > r )
			d -= t;
		else
			d += 8 - t;
	}
	if ( d != dopt )
		printf("--I - Changed digest size from %d to %d so 8<=digest<=%d and divisible by 8.\n", dopt, d, r);

	Lopt = 0;			/* cancel -L - mutually exclusive */
	kb_count = 1;		/* cancel -e */
	ascii_data = 0;		/* cancel -g1 */
}

static void optD(char *optstr) {
/* Set delimited suffix
 * -Dnn in hex 01 <= nn <= FF
 */
	BitSequence bits;
	BitSequence dd[] = "00";
	int hexmsgl = 0;
	char *p = optstr + 2;

	if ( *p == 0x00 || *(p+1) == 0x00 ) {
		dd[1] = 0x31;
		if ( *p == 0x00 )
			hexmsgl = 2;
		else
			hexmsgl = 1;
	}

	while ( *p && hexmsgl < 2 ) dd[hexmsgl++] = *p++;

	if ( ConvertDigitsToBytes(dd, &bits, 1) ) {
		printf("--I - Changed delimiter from %s to %02x; bad hex digit.\n", dd, DEFAULT_DELIMITER);
		bits = DEFAULT_DELIMITER;
	}
	if ( bits == QH_DS || bits == 0x00 ) {
		printf("--I - Changed delimiter from %02x to %02x; delimiter is zero or reserved.\n", bits, DEFAULT_DELIMITER);
		bits = DEFAULT_DELIMITER;
	}

	delimitedSuffix = bits;
}

static void opte(char *optstr) {
/* For arbitrary length output, sets
 * the number of -Ln blocks to print.
 * Must be used with -Ln.
 * -en sets the block count to n,
 * n>0; default is 1. -Ln -e5 would print
 * out 5 blocks of -Ln bits of data.
 * If this switch is not in the command
 * line, it defaults to 1.
 */
	kb_count = 1;
	int eopt = get_int(optstr+2);
	if (eopt == 0) eopt = 1;
	if (eopt < 1) {
		printf("--W - Illegal option %s ignored; block count < 1.\n", optstr);
		return;
	}
	kb_count = eopt;
}

static void optf(int argc, char **argv, int i) {
/* Create binary or ASCII hex output file used with -Ln and -en.
 * -f file     directs output from -j, -J, -K, -k, -x, -X, and -u
 *             as input to go to a binary file to use for
 *             testing and analysis. This switch will
 *             initialize the state, using a key and/or
 *             IV if present, then finalizes the state.
 *             The sponge is then squeezed as needed. Must
 *             be used with -L.
 * +f file     similar to above but uses duplexing with
 *             re-seeding every r/8-1 bytes.
 */
	unsigned char stream[WIDTH / 8], seed[WIDTH / 8];
	unsigned char stream0[WIDTH / 8];
	unsigned int k, BlockSize;
	uint64_t FileSize, bits_are_needed, squeeze;
	uint64_t inject_time = 0;
	char *sw = argv[i];
	mode Sponge;	/* duplex(+) or squeeze (-) */
	stat_file = NULL;

	/* set the mode */
	Sponge = Duplex;
	if ( argv[i][0] == '-' )
		Sponge = Squeeze;

	if (i == argc-1) {
		printf("--W - No file given for %s option; ignored.\n", sw);
		return;
	}

	if ( !Lopt ) {
		printf("--W - Missing -Ln option; %s ignored.\n", sw);
		return;
	}

	/* save output file name */
	strncpy(outfile, argv[i + 1], sizeof(outfile));

	/* Just in case some system differentiates between the two,
	 * open output file in either binary or ASCII mode */
	if ( !ascii_data )  /* binary */
		stat_file = fopen(argv[i + 1], "wb");
	else    /* ASCII */
		stat_file = fopen(argv[i + 1], "w");

	if (stat_file == NULL) {
		printf("--F - Error: %s %s: file can't be opened.\n", sw, argv[i + 1]);
		return;
	}
	file_created = 1;

	/* print time of day if not already printed */
	print_tod();

	if (Sponge == Squeeze) {	/* squeeze mode */
		hash_init();			/* initialize and process any key, IV, and/or seed */
		hash_final();			/* finalize the state and ready for squeezing */
		if ( !Finalized )
			return;
	}
	else {	/* Duplex mode */
		duplex_init();
		if ( !Initialized )
			return;

		/* Set duplex block size. Maximum input size
		 * is r-2 bits; we are using r-8 bits. */
		BlockSize = r/8 - 1;
	}

	/* amount of data to be written to the file */
	squeeze = FileSize = squeezedOutputLength / 8;
	FileSize *= kb_count;
	bits_are_needed = FileSize;

	start_timer();

	/* Just a straight squeeze of the sponge */
	if ( Sponge == Squeeze ) {	/* squeeze mode */
		while ( bits_are_needed ) {
			if ( hash_squeeze() ) {
				printf("--F - Error: Squeeze mode error during binary output in option %s.\n", sw);
				goto error;
			}

			if ( !ascii_data ) {	/* binary */
				if ( fwrite( hashval, 1, squeeze, stat_file ) != squeeze ) {
					printf("--F - Fatal I/O write error in option %s.\n", sw);
					goto error;
				}
			}
			else {	/* ASCII */
				if ( compute_hex_hashval() ) {
					printf("--F - Error: Bad or NULL hash in option %s; illegal hex value.\n", sw);
					goto error;
				}
				fprintf(stat_file, "%s", hexhashval);
			}
			bits_are_needed -= squeeze;
		}
	}
	else {	/* duplex mode */
		/* initialize and set up injection mechanism.
		 * The number of bytes generated before new material is injected
		 * is currently every 1e5 bytes or greater. */
		duplexing ( 0, 0, stream0, BlockSize ); /* capture initial stream */
		if ( Update_error == 0 ) {
			/* set up */
			if ( seed_used ) /* if random seed used */
				memcpy(seed, rseed, min(sizeof(seed), sizeof(rseed)));
			else {  /* random seed not used */
				duplexing ( 0, 0, stream, BlockSize ); /* grab another stream */
				if ( Update_error == 0 ) {
					if ( memcmp(stream0, stream, BlockSize) ) { /* is stream moving? */
						memcpy(stream0, stream, BlockSize); /* yes it is */
						memcpy(seed, stream, min(sizeof(seed), sizeof(stream)));
					}
				}
			}
		}

		/* had a set-up problem above */
		if ( Update_error ) {
			printf("--F - Error: Initialization error %d in option %s.\n", Update_error, sw);
			goto error;
		}

		while ( bits_are_needed ) {
			unsigned int datalen = min (bits_are_needed, BlockSize);

			/* update the seed */
			for(k = 0; k < datalen; k++)
				seed[k] ^= ~Duplex_out[k];

			/* generate the stream and make sure it's flowing */
			duplexing ( seed, datalen << 3, stream, datalen );	/* generate stream */
			if ( memcmp(stream0, stream, datalen) == 0 ) Update_error = 812;
			memcpy(stream0, stream, datalen);

			if ( Update_error ) {
				printf("--F - Error: Duplexing error %d during binary output in option %s.\n", Update_error, sw);
				goto error;
			}

			if ( !ascii_data ) {    /* binary */
				if ( fwrite( stream, 1, datalen, stat_file ) != datalen ) {
					printf("--F - Fatal I/O binary write error in option %s.\n", sw);
					goto error;
				}
			}
			else {  /* ASCII */
				for(k = 0; k < datalen; k++)
					fprintf(stat_file, "%02x", stream[k]);
			}
			bits_are_needed -= datalen;
		}

		/* Print out pseudo HMAC of the files fingerprint. */
		for (i = 0; i < WIDTH / 8; i++)
			Duplex_out[i] ^= 0x36;
		Update_error = quick_hash (Duplex_out, WIDTH / 8, 1024, 1, QH_DS);
		if ( Update_error ) goto error;

		for (i = 0; i < WIDTH / 8; i++)
			Duplex_out[i] ^= 0x5c;
		Update_error = quick_hash (Duplex_out, WIDTH / 8, 1024, 1, QH_DS);
		if ( Update_error ) goto error;

		printf("-- Fingerprint of '%s':\n-- ", argv[i + 1]);
		PrintBuffer (Duplex_out, max(min(C/16, BlockSize), 1));
	}

	end_timer();			/* stop the clock */
	Finalized = 1;			/* mimic behavior of squeeze mode */
	Print_Parameters();		/* print the input parameters if requested */

	/* close file and bump # of files created */
	if ( stat_file && file_created ) {
		if ( fclose(stat_file) ) {
			printf("--F - Fatal I/O error during close in option %s.\n", sw);
			file_created = 0;
			return;
		}
		file_output++;
	}

	printf ("-- Size of file '%s' in bytes: %lld\n\n", outfile, FileSize);
	file_created = 0;
	print_time();   /* print timing info if requested */
	return;
error:
	file_created = 0;
	fclose (stat_file);
}

static void optg(char *optstr) {
/* zero to create ASCII hex output file
 * one to create a binary output file
 * switch is used in conjunction with -f.
 * -gn where n = 0 or omitted, ascii_data = 0
 *     if n = 1, ascii_data = 1
 *     default is -g0 or -g (binary)
 */
	int gopt =  get_int(optstr + 2);
	if  ( gopt != 0 && gopt != 1 ) {
		printf("--W - Illegal option %s ignored; must be zero or one.\n", optstr);
		return;
	}
	if ( gopt == 0 )   /* if -g0 or -g file is binary */
		ascii_data = 0;
	else               /* -g1 file is ASCII hex file */
		ascii_data = 1;
}

static void opth() {
/* print Keccak help string with the following
 * embedded values:
 */
	unsigned int i = 0;
	unsigned int s = 0;
	char sl[16];

	printf( help_part_1,
			WIDTH - 16,                 /* maximum capacity = WIDTH-16 (bits) */
			DEFAULT_C,                  /* capacity (bits) */
			WIDTH,                      /* default width (bits) */
			DEFAULT_D,                  /* default digest size (bits) */
			DEFAULT_DELIMITER,          /* default delimiter */
			IV_SIZE * 8,                /* initialization vector size (bits) */
			IV_SIZE,                    /* initialization vector size (bytes) */
			KEY_SIZE * 8,               /* key length in bits */
			KEY_SIZE,                   /* key length in bytes */
			MSG_SIZE * 8,               /* maximum length of binary message (bits) */
			MAXSIZE,                    /* maximum number of bits to squeeze at a time */
			DEFAULT_SQUEEZE,            /* default squeeze (bits) */
			WIDTH,                      /* r = width - C */
#ifdef Reference
			DEFAULT_DELIMITER,          /* default delimiter (hex) */
			DEFAULT_ROUNDS,             /* default number of rounds */
			DEFAULT_ROUNDS              /* default number of rounds */
#else
			DEFAULT_DELIMITER           /* default delimiter (hex) */
#endif

	);

	/* print out all the presets */
	do {
		Security_strength (settings[i].d, settings[i].C, settings[i].tag, &s, sl);
		printf("\t\t%2d%4d %4d %4d  %02x  %8s   %s%d %s\n", i,
														settings[i].d,
														WIDTH - settings[i].C,
														settings[i].C,
														settings[i].D,
														settings[i].desig,
														sl,
														s,
														settings[i].tag
		);
	} while (++i < PRESETS);

	printf( help_part_2,
			WIDTH,                      /* default width (bits)     */
			DEFAULT_R,                  /* default rate (bits)      */
			WIDTH,                      /* default width (bits)     */
#ifdef Reference                        /*                          */
			MAXROUNDS,                  /* maximum number of rounds */
			DEFAULT_ROUNDS,             /* default number of rounds */
#endif                                  /*                          */
			SEEDSIZE,                   /* size of seed in bits     */
			KEY_FILE_SIZE,              /* bytes used of key file   */
			IV_FILE_SIZE,				/* bytes used for IV file   */
			KEY_ITERATIONS				/* Default PIM              */
	);
}

#ifdef Reference
static void opti(char *optstr) {
/* Turn on printing of intermediate values.
 * Currently there are 3 levels of intermediate values to print.
 * The default, 1, shows the state before and after the permutation
 * as well as the input data. Level 2 prints all level 1 values
 * plus the round constants and the rho offsets. Level 3 prints
 * all level 2 values plus the state after each round for theta,
 * rho, pi, chi, and iota. (Can be quite large.)
 * This can only be used if the reference Keccak routines are used.
*/
	print_tod();
	int iopt = get_int(optstr + 2);
	if (iopt == 0) iopt = 1;
	if (iopt < 1 || iopt > 3) {
		printf("--W - Illegal option %s ignored. Using default of one.\n", optstr);
		iopt = 1;
	}
	level = iopt;
	outFile = stdout;
	displaySetIntermediateValueFile(outFile);
	displaySetLevel(level);
	print_intermediates = 1;
}
#endif

static void optj(char *optstr) {
/* set HEX IV given as a command-line argument
 */
	optstr += 2;
	IVlen = 0;
	int maxIVlen = IV_SIZE * 2;
	while (*optstr && IVlen < maxIVlen) IV[IVlen++] = *optstr++;
	IV[IVlen] = 0;
	IVlen = ((IVlen * 4) + 7) / 8;
	burn (binary_IV, IV_SIZE);	/* initialize binary IV */
	if ( IVlen ) {	/* if not a NULL IV */
		if ( ConvertDigitsToBytes(IV, binary_IV, IVlen) ) {	/* set binary IV for hash_init */
			printf("--W - Illegal option %s ignored. Bad hex digit.\n", optstr);
			IVlen = 0;
			return;
		}
		IV_used = 1;
		IV_processed = 0;
	}
	else
		printf("--W - Null IV; option %s ignored.\n", optstr);
}

static void optJ(char *optstr) {
/* set ASCII IV if given as a command-line argument
 */
	optstr += 2;
	IVlen = 0;
	while (*optstr && IVlen < IV_SIZE) IV[IVlen++] = *optstr++;
	IV[IVlen] = 0;
	burn (binary_IV, IV_SIZE);	/* initialize binary IV */
	if ( IVlen ) {
		memcpy(binary_IV, IV, IVlen);		/* set binary IV for hash_init() */
		IV_used = 2;
		IV_processed = 0;
	}
	else
		printf("--W - Null IV; option %s ignored.\n", optstr);
}

int keybitlen = 0;	/* length of key in bits */

static void optk(char *optstr) {
/* set HEX key or salt if given as a command-line argument */
	optstr += 2;
	keylen = 0;
	int maxkeylen = KEY_SIZE * 2;
	while (*optstr && (keylen < maxkeylen)) K[keylen++] = *optstr++;
	K[keylen] = 0;
	keybitlen = keylen * 4;
	keylen = (keybitlen + 7) / 8;
	burn (binary_key, KEY_SIZE);	/* initialize binary key */
	if ( keylen ) { /* if not a NULL key */
		if ( ConvertDigitsToBytes(K, binary_key, keylen) ) {  /* set binary key for hash_init */
			printf("--W - Illegal option %s ignored.\n", optstr);
			keylen = 0;
			keybitlen = 0;
			return;
		}
	}
	key_used = 1;
	Key_processed = 0;
}

static void optK(char *optstr) {
/* set ASCII key or salt if given as a command-line argument */
	optstr += 2;
	keylen = 0;
	while (*optstr && (keylen < KEY_SIZE)) K[keylen++] = *optstr++;
	K[keylen] = 0;
	burn (binary_key, KEY_SIZE);			/* initialize binary key */
	if ( keylen ) memcpy(binary_key, K, keylen);	/* set binary key for hash_init() */
	key_used = 2;
	Key_processed = 0;
}

static void optl(char *optstr) {
/* set bit length of -m string
 * -ln where 0<=n<=Msgsize
 */
	int l = get_int(optstr+2);
	if (l < 0 || l > MSG_SIZE * 4) {
		printf("--W - Illegal option %s; length out of range. Using implied length.\n",optstr);
		lopt = 0;
	}
	else {
		mBitLength = l;
		lopt = 1;
	}
}

static void optL(char *optstr) {
/* set number of bits output
 * per squeeze
 * -Ln where 8<=n<=MAXSIZE
 *     and is divisible by 8.
 */
	Lopt = 0;
	unsigned int t;
	int L = get_int(optstr +2 );
	if (L == 0) L = DEFAULT_SQUEEZE;
	if (L < 8 || L > MAXSIZE) {
		printf("--W - Illegal option %s ignored; size out of range. Using default.\n", optstr);
		L = DEFAULT_SQUEEZE;
	}

	/* make sure squeezed length is not > maxSqueeze and is divisible by 8 */
	squeezedOutputLength = L;
	t = squeezedOutputLength % 8;
	if ( t ) {
		if (squeezedOutputLength + 8 - t > MAXSIZE)
			squeezedOutputLength -= t;
		else
			squeezedOutputLength += 8 - t;
	}
	if ( L != squeezedOutputLength ) {
		printf( "--I - Changed squeeze size from %d to %d bits so it is a multiple of 8.\n", L, squeezedOutputLength );
	}

	Lopt = 1;
	if ( kb_count < 1 ) kb_count = 1;
	d = 0;   /* must initialize with this for arbitrary length output */
}

int hexmsglen = 0;   /* length of message in bits */

static void optm(char *optstr) {
/* hash a HEX message given as a command-line argument */
	BitSequence bitdata[MSG_SIZE];
	burn (bitdata, MSG_SIZE);
	burn (Msg, MSG_SIZE * 2 + 1 );
	msgbytelen = 0;
	char *p = optstr + 2;
	while ( *p && msgbytelen < (MSG_SIZE * 2 + 1) ) Msg[msgbytelen++] = *p++;
	Msg[msgbytelen] = 0;
	hexmsglen = msgbytelen * 4;
	if (lopt) hexmsglen = mBitLength;
	if (hexmsglen) {
		if ( ConvertDigitsToBytes(Msg, bitdata, (hexmsglen + 7 ) / 8) ) {
			printf("--W - Illegal option %s ignored; bad hex digit.\n", optstr);
			return;
		}
	}
	MsgPresent = 1;
	hash_init();
	if ( hexmsglen )
		hash_update(bitdata, (DataLength) hexmsglen);
	hash_final();
}

static void optM(char *optstr) {
/* hash a message given as a command-line argument */
	char *p = optstr + 2;
	burn (Msg, MSG_SIZE * 2 + 1);
	msgbytelen = 0;
	while ( *p && msgbytelen < (MSG_SIZE * 2 + 1) ) Msg[msgbytelen++] = *p++;
	Msg[msgbytelen] = 0;
	MsgPresent = 2;
	hash_init();
	if ( msgbytelen )
		hash_update(Msg, (DataLength) (msgbytelen * 8));
	hash_final();
}

static void optn(char *optstr) {
/* Set Keccak C, r, d, nrRounds, and delimitedSuffix
 * parameters using the following rules:
 *
 * -nc	where C is the capacity; the rate is set to
 *		width - C, the digest size is C/2, the number of
 *		rounds is 24, and the delimited suffix is set
 *		to the default.
 */
	int nopt = get_int(optstr + 2);
	unsigned int t;
	if ( nopt < 0 || nopt > (WIDTH - 16) ) {
		printf("--W - Illegal option %s ignored; capacity out of range.\n", optstr);
		return;
	}
	nrRounds = DEFAULT_ROUNDS;
	delimitedSuffix = DEFAULT_DELIMITER;
	C = nopt;

	t = C % 8;
	if ( t ) {
		if (C + 8 - t > WIDTH - 16)
			C -= t;
		else
			C += 8 - t;
	}
	r = WIDTH - C;
	d = min (C / 2, 8);
	if ( nopt != C ) {
		printf( "--I - Changed capacity from %d to %d so it is a multiple of 8; rate = %d.\n", nopt, C, r );
	}

	kb_count = 1;		/* cancel -e */
	Lopt = 0;			/* cancel -L */
	ascii_data = 0;		/* cancel -g1 */
}

static void optN(char *optstr) {
/* Set Keccak C, r, d, nrRounds, and delimitedSuffix
 * parameters using the selected preset:
 *
 * -Nn	where n is the preset #: 0<=n<=PRESETS
 */
	int Nopt = get_int(optstr + 2);

	/* make sure selection is within range */
	if ( Nopt < 0)
		Nopt = 0;
	if ( Nopt >= PRESETS )
		Nopt = PRESETS - 1;

	d = settings[Nopt].d;
	C = settings[Nopt].C;
	r = WIDTH - C;
#ifdef Reference
	nrRounds = settings[Nopt].R;
#else
	nrRounds = DEFAULT_ROUNDS;
#endif
	delimitedSuffix = settings[Nopt].D;

	Tag = Nopt;         /* preset number */
	kb_count = 1;		/* cancel -e     */
	Lopt = 0;			/* cancel -L     */
	ascii_data = 0;		/* cancel -g1    */
}

static void opto(char *optstr) {
/* slow n-bit one-way function
 * -on sets number of bits to n,
 * (n >= 1) to append to the data.
 */
	oopt = get_int(optstr + 2);
	if (oopt == 0) {
		printf("--W - Illegal option %s ignored; count is zero.\n", optstr);
		oopt = 0;
		return;
	}
	Oopt = 0;   /* mutually exclusive */
}

static void optO(char *optstr) {
/* slow n-Byte one-way function
 * -On sets number of Bytes to n,
 * (n >= 1) to append to the data.
 */
	Oopt = get_int(optstr + 2);
	if (Oopt == 0) {
		printf("--W - Illegal option %s ignored; count is zero.\n", optstr);
		Oopt = 0;
		return;
	}
	oopt = 0;   /* mutually exclusive */
}

static void optp() {
/* turn on printing of input parameters */
	print_parameters = 1;
	parameters_not_printed = 1;
}

static void optq(int argc, char **argv, int i) {
/* +/-q infile outfile  Encrypt or Decrypt a file. Stream cipher.
 *						Reads infile and adds (modulo 2) the key stream
 *						The result is written to outfile.
 */
	FILE *src_file;
	FILE *crypt_file;
	uint64_t bytes;
	char *sw = argv[i];

	mode Direction = Encrypt;   /* Encrypt */
	if ( argv[i][0] == '-' )    /* Decrypt */
		Direction = Decrypt;
	int j = 0;

	if ( i == argc-1 || i == argc-2 ) {
		printf("--F - Two files required for %s option; option ignored.\n", sw);
		return;
	}

	src_file = fopen(argv[i+1], "rb");
	if ( src_file == NULL || feof(src_file) ) {
		printf("--F - Error: Source file %s can't be read or is empty; %s option ignored.\n", argv[i+1], sw);
		if ( src_file ) fclose (src_file);
		return;
	}

	crypt_file = fopen(argv[i+2], "wb");
	if (crypt_file == NULL) {
		printf("--F - Error: - Output file %s can't be opened; %s ignored.\n", argv[i+2], sw);
		fclose (src_file);
		return;
	}

	/* set up sponge for squeeze mode */
	print_tod();	/* print time of day if not already printed */
	d = 0;			/* set digest length to 0 (arbitrary length output) */
	Lopt = 1;		/* set -L too but we will set the value not -L option */

	/* set the squeezing size to a multiple of the rate
	 * that is <=  MAXSIZE */
	squeezedOutputLength = MAXSIZE - MAXSIZE % r;
	uint32_t size = squeezedOutputLength << 3;

	Encoding = 1;							/* flag so seed can't be used */
	hash_init();							/* initialize and process any key and/or IV */
	hash_final();							/* finalize the state and ready for squeezing */
	Encoding = 0;
	if ( !Finalized ) return;				/* we had a problem so bail */

	BitSequence *data = (BitSequence *) malloc(size);
	if ( data == NULL ) {
		printf("--F - Error: Option %s file buffer exhausted.\n", sw);
		fclose (src_file);
		fclose (crypt_file);
		return;
	}

	start_timer();	/* start the clock */

	/* read the input file and squeeze the sponge */
	while ( (bytes = fread (data, 1, size, src_file)) != 0 ) {
		if ( hash_squeeze() ) {
			printf("--F - Error in option %s during key stream output.\n", sw);
			fclose (src_file);
			fclose (crypt_file);
			burn (data, size);
			free ( data );
			return;
		}

		/* Encrypt or decrypt the data */
		for (j = 0; j < bytes; j++)
			data[j] ^= hashval[j];

		/* write the data to the output file */
		if ( fwrite( data, 1, bytes, crypt_file ) != bytes ) {
			printf("--F - Fatal I/O write error in option %s.\n", sw);
			fclose (src_file);
			fclose (crypt_file);
			burn (data, size);
			free ( data );
			return;
		}
	}

	end_timer();			/* stop the clock */
	Print_Parameters();		/* print parameters if requested */
	print_time();			/* print timing data if wanted */

	/* zero and free buffer */
	burn (data, size);
	free ( data );

	/* Close the files and check for errors. Very important
	 * as we don't want anyone to shred anything if a problem occurred. */
	int err = fclose(src_file);
	if ( err )
		printf("--F - Error: Fatal I/O error during close of %s.\n"
				"--F   DO NOT DELETE ANY FILES. Check disk for errors.\n", argv[i+1]);
	if ( fclose(crypt_file) ) {
		printf("--F - Error: Fatal I/O error during close of %s.\n"
					"--F   DO NOT DELETE ANY FILES. Check free space of disk.\n", argv[i+2]);
		return;
	}
	if ( !err ) file_output++;	/* bump the output file counter */
}

static void optQ(int argc, char **argv, int i) {
/* +/-Q infile outfile  Encrypt(+) or Decrypt(-) a file. Stream cipher.
 *						Like -q this option reads infile and XORs
 *						it with the key stream generated from a
 *						key and/or a keyfile. This option demonstrates
 *						duplexing. A key is required input.
 *
 *						The IV is not really a NONCE, ie. reuseable. If no IV
 *                      is specified, the hashed compliment of the key is used;
 *						If the IV IS specified, the above is added to the IV
 *						specified.
 *
 *						The accumulator is a vector that is the sum
 *						(modulo 2) of all previous sponge outputs. This
 *						becomes the fingerprint of the file processed and is
 *						printed at the end of the job. If the fingerprint
 *						printed at the end of the decryption process does not
 *						match the fingerprint produced when the file was
 *						encrypted, then the process has been subverted and
 *						the file cannot be authenticated or trusted.
 *
 *					1.	The data from file infile is XORed with the "last block"
 *                      of cipher text or the IV if this is the first block.
 *
 *					2.	The key stream from step one is then summed (modulo 2)
 *						with the data from step one, this then becomes the
 *						"last block" of cipher text, and is written to file
 *						outfile.
 *
 *					3.	go to step one.
 */

	FILE *src_file;
	FILE *crypt_file;
	unsigned char key_stream[WIDTH / 8];
	unsigned int j, l;
	int offset, bytes;
	unsigned int buffer_not_empty, datalength;

	/* Initialize and set mode -- Encrypt(+) or Decrypt(-) */
	char *sw = argv[i];
	mode Direction = Encrypt;	/* Encrypt */
	if ( argv[i][0] == '-' )
		Direction = Decrypt;	/* Decrypt */

	if ( i == argc - 1 || i == argc - 2 ) {
		printf("--F - Error: Two files required for %s option; %s ignored.\n", sw, sw );
		return;
	}

	/* Key is required for this option */
	if ( !xopt && key_used == 0 ) {
		printf("--F - Error: bad duplex configuration; key required with %s\n", sw);
		return;
	}

	src_file = fopen(argv[i+1], "rb");
	if ( src_file == NULL || feof(src_file) ) {
		printf("--F - Error: Source file %s can't be read or is empty; %s ignored.\n", argv[i + 1], sw);
		if ( src_file ) fclose (src_file);
		return;
	}

	crypt_file = fopen(argv[i + 2], "wb");
	if ( crypt_file == NULL ) {
		printf("--F - Error: - Output file %s can't be opened; %s ignored.\n", argv[i + 2], sw);
		fclose (src_file);
		return;
	}

	/* Save the file name */
	burn(GenIVfile, (MAXSIZE / 8));
	if (Direction == Encrypt)
		strncpy(GenIVfile, argv[i + 2], min(strlen(argv[i + 2]), MAXSIZE / 8) );
	else /* decrypting */
		strncpy(GenIVfile, argv[i + 1], min(strlen(argv[i + 1]), MAXSIZE / 8) );

	Initialized = 0;
	print_tod();			/* print time of day if not already printed */
	start_timer();			/* start the clock */

	/* Process key */
	if ( !Key_processed ) Process_Key( &Key_bytes_used );
	if ( Update_error ) goto error;
	if (Key_bytes_used == 0) {
		printf("--F - Error: Option %s Must use a key.\n", sw);
		goto error;
	}

	/* Process IV */
	if ( !IV_processed ) Process_IV( &IV_bytes_used );
	if (Update_error) goto error;

	/* Calculate file buffer size to be the greater of the IV size and
	 * the key size then making it a multiple of the block size and at least
	 * DISK_BLOCK_SIZE bytes long. */
	int BlockSize = (r >> 3) - 1;   /* Maximum duplex input size is r-2 bits but we will use r-8 bits. */
	SETHBL( BlockSize, max(MAXSIZE / 8, DISK_BLOCK_SIZE) )

	/* allocate input buffer */
	unsigned char *data = (unsigned char *) malloc( HBL );
	if ( data == NULL ) {
		printf("--F - Error: Option %s file buffer memory pool exhausted.\n", sw);
		fclose (src_file);
		fclose (crypt_file);
		return;
	}

	/* allocate chaining buffer */
	unsigned char *chain_vector = (unsigned char *) malloc( HBL );
	if ( chain_vector == NULL ) {
		printf("--F - Error: Option %s chain buffer memory pool exhausted.\n", sw);
		fclose (src_file);
		fclose (crypt_file);
		free ( data );
		return;
	}

	/* allocate cipher text buffer */
	unsigned char *cipher_text = (unsigned char *) malloc( HBL );
	if ( cipher_text == NULL ) {
		printf("--F - Error: Option %s data buffer memory pool exhausted.\n", sw);
		fclose (src_file);
		fclose (crypt_file);
		free ( data );
		free (chain_vector);
		return;
	}

	/* Initialize the chain vector and cipher_text vector with IV */
	burn (chain_vector, HBL);
	memcpy (chain_vector, binIV, HBL);
	memcpy (cipher_text, chain_vector, HBL);

	/* Initialize the duplex state */
	Encoding = 1;   /* Flag so seed can't be used in init */
	duplex_init();  /* initialize duplex */
	Encoding = 0;

error:

	if ( !Initialized ) {
		printf("--F - Error: Option %s processing error.\n", sw);
		free ( data );
		free (chain_vector);
		free (cipher_text);

		fclose (src_file);
		fclose (crypt_file);
		burn (key_data, sizeof(key_data));
		burn (binary_key, sizeof(binary_key));
		burn (binkey, MAXSIZE / 8);
		burn (K, sizeof(K));
		burn (IV_data, sizeof(IV_data));
		burn (binary_IV, sizeof(binary_IV));
		burn (binIV, MAXSIZE / 8);

		burn (chain_vector, HBL);
		burn (cipher_text, HBL);
		burn (key_stream, WIDTH / 8);
		burn (data, HBL);
		burn (Duplex_out, WIDTH / 8);
		return;
	}

	/* read the input file and do the work */
	while ( (bytes = fread (data, 1, HBL, src_file)) != 0 ) {
		buffer_not_empty = bytes;
		offset = 0;

		if (Direction == Encrypt)
			/* if encrypting, XOR the plain text with the previous disk block of
			 * cipher text. If decrypting, set the chain vector to the cipher text just read. */
			for (l = 0; l < bytes; l++)
				data[l] ^= chain_vector[l];	
		else    /* Decrypt */
			memcpy(chain_vector, data, bytes);

		/* process the input buffer BlockSize bytes at a time */
		while ( buffer_not_empty ) {
			datalength = min (buffer_not_empty, BlockSize);

			/* feed the sponge with r/8-1 bytes of the previous block
			 * of cipher text if encrypting, or the cipher text just read
			 * if decrypting. Generate the key stream. */
			if ( Direction == Encrypt ) {
				duplexing(chain_vector + offset, datalength << 3, key_stream, datalength);
				if ( Update_error )
					goto error;
			}
			else {   /* decrypt */
				duplexing(cipher_text + offset, datalength << 3, key_stream, datalength);
				if ( Update_error )
					goto error;
			}

			/* XOR data read with the key stream */
			for (j = offset, l = 0; j < offset + datalength; j++, l++)
				data[j] ^= key_stream[l];

			/* update our position in the buffer */
			buffer_not_empty -= datalength;
			offset += datalength;	
		}
 
		/* If encrypting, set the chain vector to the cipher text. If decrypting, XOR
		 * the data with the previous cipher text. Finally, set the previous cipher
		 * text to the current cipher text */
		if ( Direction == Encrypt )
			memcpy(chain_vector, data, bytes);
		else {	/* Decrypt */
			for (l = 0; l < bytes; l++)
				data[l] ^= cipher_text[l];
			memcpy ( cipher_text, chain_vector, bytes);
		}

		/* write the data to the output file */
		if ( fwrite( data, 1, bytes, crypt_file ) != bytes )
		/* Fatal I/O write error */
			goto error;
	}

	end_timer();                                /* stop the clock */
	burn (key_stream, WIDTH / 8);               /* zero the key stream */
	burn (data, HBL);                           /* file data */
	burn (chain_vector, HBL);                   /* chain block */
	burn (cipher_text, HBL);                    /* cipher text */
	free (chain_vector);                        /* release it */
	free (data);                                /* deallocate the input buffer */
	free (cipher_text);                         /* deallocate the cipher text buffer */
	Finalized = 1;                              /* needed here to mimic hash_final() */
	Initialized = 1;							/* reset */
	Print_Parameters();                         /* print parameters if requested */

	/* print out the fingerprint of the file */
	for (i = 0; i < WIDTH / 8; i++)
		Duplex_out[i] ^= 0x36;
	Update_error = quick_hash (Duplex_out, WIDTH / 8, 1024, 1, QH_DS);
	if ( Update_error ) goto error;

	for (i = 0; i < WIDTH / 8; i++)
		Duplex_out[i] ^= 0x5c;
	Update_error = quick_hash (Duplex_out, WIDTH / 8, 1024, 1, QH_DS);
	if ( Update_error ) goto error;

	printf("-- Fingerprint of '%s':\n-- ", GenIVfile);
	unsigned int hm = min(min(C / 16, BlockSize), 32);
	PrintBuffer (Duplex_out, hm);
	burn (Duplex_out, WIDTH / 8);	/* zero the accumulator */

	print_time();	/* print timing data if wanted */

	/* Close the files and check for errors. This is critical as we
	 * don't want the user to shred anything if a problem occurred. */
	int err = fclose(src_file);
	if ( err )
		printf("--F - Error: Fatal I/O error during close of %s.\n"
				"--F   DO NOT DELETE ANY FILES. Check free space of disk.\n", argv[i + 1]);
	if ( fclose(crypt_file) ) {
		printf("--F - Error: Fatal I/O error during close of %s.\n"
				"--F   DO NOT DELETE ANY FILES. Check free space of disk.\n", argv[i + 2]);
		return;
	}
	if ( err ) return;

	file_output++;   /* bump the output file counter */
}

static void optr(char *optstr) {
/* set Keccak rate
 * -rn where 16<=n<=width and n must be a multiple of 8
 * set Capacity to match this rate.
*/
	unsigned int t;
	unsigned int ropt = get_int(optstr + 2);
	if ( ropt == 0 ) ropt = DEFAULT_R;
	r = ropt;

	if ( r < 16 ) r = 16;
	if ( r > WIDTH ) r = WIDTH;
	t = r % 8;

	/* if we have to change r, try to lower it first. If out of range, then raise it. */
	if ( t ) {
		if ( r - t < 16 )
			r += 8 - t;
		else
			r -= t;
	}
	C = WIDTH - r;

	if ( ropt != r ) {
		printf( "--I - Changed rate from %d to %d so 16<=r<=%d and divisible by 8; capacity = %d.\n", ropt, r, WIDTH, C );
	}
}

#ifdef Reference
static void optR(char *optstr) {
/* set number of Keccak rounds
 * -Rn where 1<=n<=MAXROUNDS
 * This can only be used if the reference Keccak routines are used.
 * If more than MAXROUNDS rounds are needed, change the following
 * statement in KeccakF-1600-reference.c:
 *
 * UINT64 KeccakRoundConstants[xx];
 *
 * and in KeccakF-1600-reference32BI.c
 *
 * UINT32 KeccakRoundConstants[xx][2];
 *
 * from xx to the setting of MAXROUNDS to reflect the additional rounds.
 *  ie if MAXROUNDS is 80, change xx to 80
 */
	int opt = get_int(optstr + 2);
	if ( opt == 0 ) opt = DEFAULT_ROUNDS;
	nrRounds = opt;

	if ( opt < 1 )
		nrRounds = 1;
	if ( opt > MAXROUNDS )
		nrRounds = MAXROUNDS;
	if ( nrRounds != opt )
		printf("--I - Changed rounds to %d from %d so 16<=r<=%d\n", nrRounds, opt, WIDTH);
}
#endif

static void opts(char *optstr) {
/* Setup time trials for state initialization
 * and any other parameters such as a key, key file,
 * IV, IV file, and/or a seed as specified on the
 * command line before -s. This is also used to test
 * if KEY_ITERATIONS is sufficiently large in computing
 * cost to make a rainbow table or dictionary attack
 * infeasible when a key is used (-K, or -k, and/or -x).
 */
	uint64_t i;
	print_tod();
	double mps;

	trials = strlen(optstr) > 2 ? get_int(optstr + 2) : 1;

	/* save SOME program settings
	 * and reset the ones we need to change */
	Save_settings();
	print_key_ok = 1;
	print_parameters = 1;
	print_times = 2;
	sopt = 1;

	/* calculate time to initialize Keccak as configured via command line*/
	print_tod();
	init_counters_flags();
	start_timer();
	for (i = 0; i < trials; i++) {
		Key_processed = 0;
		IV_processed = 0;

		hash_init();
		if ( !Initialized ) {
			printf("--F - Initialization error during testing in option %s.\n", optstr);
			trials = 0;
			Restore_settings();
			sopt = 0;
			return;
		}
	}
	end_timer();
	Finalized = 1;

	Print_Parameters();

	printf("-- Setup trials as configured above --\n");
	printf("-- Setup trials = %lld\n",(long long int)trials);
	printf("-- Clock ticks / setup = %lld\n", (long long int)(elapsed_ticks/trials));
	mps = (elapsed_time * (double)1e6);
	if ( mps * (double)1e7 > (double)1 )
		printf("-- Microseconds / setup = %g\n\n",
			mps);
	else
		printf("-- Microseconds / setup = ** Too small to print **\n\n");

	/* print timing info */
	print_time();

	/* restore settings */
	Restore_settings();
	trials = 0;
	sopt = 0;
}

static void optS() {
/* allow key (-k or -K) to be printed like the other parameters. For use
 * with the -p and the -c option. Useful for testing. Default is to not
 * print the key. */
	print_key_ok = 1;
}

static void optt() {
/* turn on timing printout - for each hash or squeeze and grand totals */
	print_times = 2;
}

static void optT() {
/* turn on timing printout - grand totals only */
	print_times = 1;
}

static void optu() {
/* generate a seed of size SEEDSIZE if -u is given as a command-line argument */
	int i;
	uint32_t offset;
	static int first_seed = 1;
	int ran, ran1;
	static unsigned char rseed0[SEEDSIZE / 8], rseed1[SEEDSIZE / 8];
	unsigned char ranseed[32 / 8];
	static unsigned char NullVector[SEEDSIZE / 8], HighVector[SEEDSIZE / 8];

	/* number of SEEDSIZE / 8 byte blocks to poll from o/s */
	/* as well the number of times to hash it */
	int polling = SEED_HASH_COUNT;
	seed_used = 0;

	/* get the first batch of random data.
	   ranseed used intentially without init.
	   Because of AMD, rdrand Always == 0xFFFFFFFFFFFFFFFF
	   Make sure it's not all 1's */
	if ( first_seed ) {
		burn (NullVector, SEEDSIZE / 8);
		for (i=0; i < SEEDSIZE / 8; i++)
			HighVector[i] = 0xFF;
#ifdef __mingw__
		srand(time(NULL)); /* initialize */
		ran = rand(); /* throw away */
		for (offset=0; offset < SEEDSIZE / 8; offset += sizeof(ranseed)) {
			ran = rand();
			ran1 = rand();
			if ( ran == 0
				|| ran == ran1
				|| ran == 0xFFFFFFFFFFFFFFFF
				|| ran1 == 0
				|| ran1 == 0xFFFFFFFFFFFFFFFF ) {
				Update_error = 9;
				goto error;
			}

			ranseed [0] ^= (ran1 >> 8) & 0xFF;
			ranseed [1] ^= ran1 & 0xFF;
			ranseed [2] ^= (ran >> 8) & 0xFF;
			ranseed [3] ^= ran & 0xFF;
			memcpy(rseed0 + offset, ranseed, sizeof(ranseed));
		}
#else
		randombytes (rseed0, SEEDSIZE / 8); /* throw away */
		randombytes (rseed0, SEEDSIZE / 8);
#endif
		if ( memcmp(rseed0, NullVector, SEEDSIZE / 8) == 0
			|| memcmp(rseed0, HighVector, SEEDSIZE / 8) == 0 ) {
			Update_error = 9;
			goto error;
		}
		first_seed = 0;
	}

	do {
		/* Get random data from the O/S. If it is the same as the previous
		 * seed generated, a big problem. */
#ifdef __mingw__
		for (offset=0; offset < SEEDSIZE / 8; offset += sizeof(ranseed)) {
			ran = rand();
			ran1 = rand();
			ranseed [0] ^= (ran1 >> 8) & 0xFF;
			ranseed [1] ^= ran1 & 0xFF;
			ranseed [2] ^= (ran >> 8) & 0xFF;
			ranseed [3] ^= ran & 0xFF;
			memcpy(rseed + offset, ranseed, sizeof(ranseed));
		}
#else
		randombytes (rseed, SEEDSIZE / 8);
#endif
		/* exit if the same as last seed - big problem */
		if ( memcmp(rseed0, rseed, SEEDSIZE / 8) == 0 ) { 
			Update_error = 9;
			goto error;
		}

		/* save current seed as previous seed
		 * and accumulate. rseed1 is intentially used
		 * uninitialized */
		memcpy(rseed0, rseed, SEEDSIZE / 8);
		for (i = 0; i < SEEDSIZE / 8; i++)
			rseed1[i] ^= rseed[i];

	} while ( --polling );

	/* copy the sum of the random bits generated and
	 * hash the result using SEED_HASH_COUNT squeezes */
	memcpy(rseed, rseed1, SEEDSIZE / 8);
	Update_error = quick_hash (rseed, SEEDSIZE / 8, 1024, SEED_HASH_COUNT, QH_DS);

error:

	if ( Update_error ) {
		Update_error += 200;
		printf("--F - Seed generation error %d; Seed set to NULL.\n", Update_error);
		burn(rseed, SEEDSIZE / 8);
		first_seed = 1;
		return;
	}

	seed_used = 1;
}

static void optv() {
/* print version information */
	printf("sha3sum V%s.%s.%s %s %s %s\n",version_major, version_minor, version_rev, month, year, class);
	printf("Environment: %s, %s\n", OS, CC);
	printf("Copyright (c) %s McDevitt Heavy Industries, Ltd. (MHI) Philippines.\n", year);
	printf("This is free software, and you are welcome to redistribute it, governed\n");
	printf("by the GNU general public license, Version 2.0 only.\n");
}

static void optx(int argc, char **argv, int i) {
/* Open file for use as a keyfile. If -k or -K is
 * also used, they are added together.
 * -x file     opens a file in binary mode and reads
 *             the first KeyFileSize bytes. If the
 *             file is shorter, then the input is
 *             padded with zeros to make it
 *             KeyFileSize bytes.
 */
	FILE *key_file;
	uint64_t bytes;
	xopt = 0;

	if (i == argc-1) {
		printf("--W - No file given for -x option; ignored.\n");
		return;
	}
	key_file = fopen(argv[i+1], "rb");
	if (key_file == NULL) {
		printf("--W - Illegal option -x %s: file can't be opened; ignored.\n", argv[i+1]);
		return;
	}

	burn (key_data, KEY_FILE_SIZE);
	bytes = fread (key_data, 1, KEY_FILE_SIZE, key_file);
	fclose(key_file);
	if ( bytes == 0 ) {
		printf("--W - Illegal option -x %s: file is NULL; ignored.\n", argv[i+1]);
		return;
	}

	if ( bytes < KEY_FILE_SIZE ) {
		printf("--I - Key file %s only contained %lld byte", argv[i+1], bytes);
		if ( bytes>1 )
			printf("s.\n");
		else
			printf(".\n");
		printf("--I   Key padded with %ld zero byte", (KEY_FILE_SIZE-bytes));
		if ( (KEY_FILE_SIZE-bytes) > 1 )
			printf ("s.\n");
		else
			printf (".\n");
	}

	Key_processed = 0;
	quick_hash ( key_data, KEY_FILE_SIZE, 1024, 1, QH_DS );
	if ( Update_error ) {
		printf("--W - Key file processing error; '-x %s' ignored ", argv[i+1]);
		return;
	}

	xopt = 1;
	burn (KeyFileSpec, sizeof(KeyFileSpec));
	memcpy(KeyFileSpec, argv[i+1], min (FILESPEC_SIZE - 3, strlen(argv[i+1])));
}

static void optX(int argc, char **argv, int i) {
/* Open file for use as an initialization vector.
 * If -j or -J is also used, they are added together.
 * -X file     opens a file in binary mode and reads
 *             the first IVFileSize bytes. If the
 *             file is shorter, then the input is
 *             padded with zeros to make it
 *             IVFileSize bytes.
 */
	FILE *IV_file;
	uint64_t bytes;
	Xopt = 0;

	if (i == argc-1) {
		printf("--W - No file given for -X option; ignored.\n");
		return;
	}
	IV_file = fopen(argv[i+1], "rb");
	if (IV_file == NULL) {
		printf("--W - Illegal option -X %s: file can't be opened; ignored.\n", argv[i+1]);
		return;
	}

	burn (IV_data, IV_FILE_SIZE);
	bytes = fread (IV_data, 1, IV_FILE_SIZE, IV_file);
	fclose(IV_file);
	if ( bytes == 0 ) {
		printf("--W - Illegal option -X %s: file is NULL; ignored.\n", argv[i+1]);
		return;
	}

	if ( bytes < IV_FILE_SIZE ) {
		printf("--I - IV file %s only contained %lld byte", argv[i+1], bytes);
		if ( bytes>1 )
			printf("s.\n");
		else
			printf(".\n");
		printf("--I   IV padded with %ld zero byte", (IV_FILE_SIZE - bytes));
		if ( (IV_FILE_SIZE - bytes > 1) )
			printf("s.\n");
		else
			printf(".\n");
	}

	IV_processed = 0;
	quick_hash ( IV_data, IV_FILE_SIZE, 1024, 1, QH_DS );
	if ( Update_error ) {
		printf("--W - IV file processing error; '-X %s' ignored ", argv[i+1]);
		return;
	}

	Xopt = 1;
	burn (IVFileSpec, sizeof(IVFileSpec));
	memcpy(IVFileSpec, argv[i+1], min (FILESPEC_SIZE - 3, strlen(argv[i+1])));
}

static void opty(char *optstr) {
/* set key iteration count
 * -yn where n >= 10000
 */
	uint64_t k = get_int(optstr + 2);
	if (k < 10000 ) {
		printf("--W - Illegal option %s is < minimum of 10,000. Using default (%d)\n",optstr, KEY_ITERATIONS);
		pim = KEY_ITERATIONS;
	}
	else
		pim = k;
}

/*************************************************************************
** End of command line options                                          **
*************************************************************************/

/*************************************************************************
 **                U T I L I T Y   R O U T I N E S                      **
 ************************************************************************/
static void Save_settings() {
/* save SOME program settings */
	save_d = d;
	save_C = C;
	save_D = delimitedSuffix;
	save_R = nrRounds;
	save_Lopt = Lopt;
	save_squeezedOutputLength = squeezedOutputLength;
	save_MsgPresent = MsgPresent;
	save_kb_count = kb_count;
	save_Oopt = Oopt;
	save_oopt = oopt;
	save_key_used = key_used;
	save_IV_used = IV_used;
	save_lopt = lopt;
	save_pk = print_key_ok;
	save_pp = print_parameters;
	save_pt = print_times;
	save_final = Finalized;
	save_init = Initialized;
	save_KP = Key_processed;
	save_IVP = IV_processed;
}

static void Restore_settings() {
/* restore the settings previously saved. */
	d = save_d;
	C = save_C;
	r = WIDTH - C;
	delimitedSuffix = save_D;
	nrRounds = save_R;
	Lopt = save_Lopt;
	squeezedOutputLength = save_squeezedOutputLength;
	MsgPresent = save_MsgPresent;
	kb_count = save_kb_count;
	Oopt = save_Oopt;
	oopt = save_oopt;
	key_used = save_key_used;
	IV_used = save_IV_used;
	lopt = save_lopt;
	print_times = save_pt;
	print_key_ok = save_pk;
	print_parameters = save_pp;
	Finalized = save_final;
	Initialized = save_init;
	Key_processed = save_KP;
	IV_processed = save_IVP;
}

#ifndef __mingw__
static void randombytes(unsigned char *x,unsigned long long xlen) {
/* Thank you to D. J. Bernstein for this (nacl)
 */
	int i;
	static int rd = -1;

	if (rd == -1) {
		for (;;) {
			rd = open("/dev/urandom",O_RDONLY);
			if (rd != -1) break;
			sleep(1);
		}
	}

	while (xlen > 0) {
		i = xlen;
		i = read(rd,x,i);
		if (i < 1) {
			sleep(1);
			continue;
		}

		x += i;
		xlen -= i;
	}
}
#endif

static void check_line(char *line) {
	/* print filename if its hash doesn't agree with what's given in line
	 */
	char *x;
	char hexhashvalFile[MAXSIZE/8 + 1];
	int hexhashlen;
	char filename[FILESPEC_SIZE];
	char decfilename[FILESPEC_SIZE];
	int filenamelen;
	/* collect hash value */
	x = line;
	hexhashlen = 0;
	while ( *x && *x != ' ' && hexhashlen < (MAXSIZE/8 + 1) )
		hexhashvalFile[hexhashlen++] = *x++;
	hexhashvalFile[hexhashlen] = 0;
	if (*x != ' ') {
		printf("--F - Error: format error in hash check file line: %s\n",line);
		return;
	}
	x++;
	/* collect filename and decode it */
	filenamelen = 0;
	while (*x && *x != '\n' && filenamelen < (FILESPEC_SIZE - 3))
		filename[filenamelen++] = *x++;
	filename[filenamelen] = 0;
	decode(decfilename,filename);
	if (filename[0] == '-') {
		/* handle "filenames" starting with '-' specially,
		 * even though legitimate filenames may start with '-'.
		 */
		if (filenamelen == 1)
			return; 	/* skip standard input */
		switch( filename[1] ) {
			case 'm': optm(decfilename); break;
			case 'M': optM(decfilename); break;
			case 'b': optb(decfilename); break;
			case 'B': optB(decfilename); break;
			default:  hash_file(decfilename);
						if (file_error) return;
						break;
		}
	}
	else {
		/* now compute hash of file */
		hash_file(decfilename);
		if(file_error) return;
	}
	if (strcmp(hexhashvalFile,(char *)hexhashval) != 0) {
		if ( print_intermediates || print_parameters || print_times )
			printf("--F - Error: hash verification failed for: %s\n",decfilename);
		else
			printf("%s\n",decfilename);
	}
}

static int compute_hex_hashval() {
/*
 * Convert hashval into hexadecimal, and
 * save result in hexhashval
 * This will be a zero-terminated string of length (d/4).
 * Assumes that hashval has already been "trimmed" to correct
 * length.
 *
 * Returns one of the following:
 *    0 = SUCCESS
 *    1 = FAIL
 */
	int i;
	static unsigned char hex_digits[] = "0123456789abcdef";

	/* If the sponge was initialized with d=0,
	 * then the hash is of arbitrary length.
	 * Otherwise, the hash has a fixed length. */

	for (i=0;i<((d+7)>>3);i++) {
		hexhashval[i<<1] = hex_digits[ ((hashval[i])>>4) & 0xf ];
		hexhashval[(i<<1)+1] = hex_digits[ (hashval[i]) & 0xf ];
	}
	/* insert zero string termination byte at position d/4
	 * and check to see if NULL
	 */
	hexhashval[(d+3)>>2] = 0;
	if ( (char *)hexhashval == NULL )
		return (Fail);
	else
		return (Success);
}

static BitSequence ConvertDigitToNumber(BitSequence digit) {
/*
 * ConvertDigitToNumber() converts a single ASCII hexadecimal digit
 * to its numeric equivalent in the range 0x0-0xf.
 */
	if (digit != 0x00)
		if (!isxdigit(digit)) return ('x');
	if (isdigit(digit))
		return ((BitSequence) (digit-'0'));

	if (islower(digit))
		return ((BitSequence) (digit-'a'+0xa));

	/* Apparently, it's an upper case letter */
	return ((BitSequence) (digit-'A'+0xa));
}

static int ConvertDigitsToBytes(BitSequence* digits, BitSequence* bytes, int n) {
/* ConvertDigitsToBytes() converts a sequence of pairs of ASCII hex
 * digits into a sequence of bytes.  It takes an argument, n, which
 * specifies how many bytes will be produced: 2n hex digits get
 * converted to n bytes.
 */
	int i;
	for (i = 0; i < n<<1; i += 2) {
		BitSequence msn = ConvertDigitToNumber(digits[i]);
		BitSequence lsn = ConvertDigitToNumber(digits[i+1]);
		if (msn == 'x' || lsn == 'x') return (Fail);
		bytes[i >> 1] = (BitSequence) ((msn << 4) | lsn);
	}
	return (Success);
}

/*************************************************************************
** End of utility routines                                              **
*************************************************************************/

static void print_hash(char *filename) {
/*************************************************************************
** Routine to print hashvalue filename line and any other info requested**
** Prints time_of_day first if it hasn't been printed already.          **
*************************************************************************/

	uint64_t cnt;
	unsigned long 
	int k, l;
	if ( !Finalized ) return;	/* problem or nothing to do */
	print_tod();
	/* print configuration when necessary for -c option */
	print_config();
	/* print input parameters if selected and not already printed */
	Print_Parameters();

	if ( Lopt ) {   /* If here, arbitrary length output - squeeze */
		if ( kb_count > 1 ) {
			printf("\n-- %lld blocks", kb_count);
			printf(" of %d byte", squeezedOutputLength / 8);
			if ( squeezedOutputLength / 8 > 1 ) printf("s");
			printf(" output from the hash of %s\n", filename );
		}
		for (cnt = 0; cnt < kb_count; cnt++) {
			if ( hash_squeeze() ) {
				printf("--F - Squeeze error during stdio hex output.\n");
				return;
			}
			/* print out hash */
			printf("       ");
			int dlen = squeezedOutputLength / 8;
			int offset = 0;
			while (dlen > 0) {
				l = min (squeezedOutputLength / 8, 32);
				for(k = offset; k < l + offset; k++)
					printf("%02x", hashval[k]);
				dlen -= l;
				offset += 32;
				if ( dlen > 0 )
					printf("\n       ");
				else
					printf("\n");
			}
		}
		printf("\n");
	}
	else {
		/* If here, fixed length output selected
		 * Print the hash and file name line.
		 * Finally; that was what all this was for... */
		if ( print_intermediates )
			printf("\n-- Final hash value is:\n");
		printf("%s %s\n", hexhashval, filename);
	}
	print_time();   /* print timing info if requested */
}

int cfgnotprt = 1;

static void print_config() {
/* Print configuration switches ONLY when they
 * are necessary so that -c can reconfigure sha3sum
 * with the same parameters used previously.
 * This only prints the switches that have
 * non-default values. For security, -k or -K will
 * not be printed unless -S is used. In short,
 *
 * when using the -c option, -k, -K, -x, -X
 * must be entered before -c on the command line.
 */
	if ( print_switches && cfgnotprt && kb_count < 2 && !print_intermediates && !print_parameters ) {
		if ( C != DEFAULT_C ) printf("-C%d\n", C);
		if ( r != DEFAULT_R ) printf("-r%d\n", r);
		if ( d != DEFAULT_D && !Lopt ) printf("-d%d\n", d);
		if ( squeezedOutputLength != DEFAULT_SQUEEZE && Lopt ) printf("-L%d\n", squeezedOutputLength);
		if ( delimitedSuffix != DEFAULT_DELIMITER ) printf("-D%02X\n", delimitedSuffix);
		if ( key_used == 1 && print_key_ok ) printf("-k%s\n", K);   /* print only if specifically requested */
		if ( key_used == 2 && print_key_ok ) printf("-K%s\n", K);   /* print only if specifically requested */
		if ( yopt ) printf("-y%lld\n", pim);
		burn (K, sizeof(K));

		if ( IV_used == 1 ) printf("-j%s\n", IV);
		if ( IV_used == 2 ) printf("-J%s\n", IV);
		if (oopt) printf("-o%lld\n", oopt);
		if (Oopt) printf("-O%lld\n", Oopt);
#ifdef Reference
		if ( nrRounds != DEFAULT_ROUNDS ) printf("-R%d\n", nrRounds);
#endif
		cfgnotprt = 0;
	}
}

static void Print_Parameters() {
/* prints out input parameters if requested
 */
	int bytes = 0;
	int bits = 0;
	unsigned int i, j, dlen, offset;
	if ( print_parameters == 1 && parameters_not_printed && Finalized ) {   /* print input parameters if requested */
		print_tod();
		printf("\n-- Algorithm: %s (%s)\n", settings[0].desig, settings[0].tag);
		printf("-- C = %7d (capacity)\n", C);
		printf("-- r = %7d (bit rate)\n", r);
		if ( Lopt ) {
			printf("-- L = %7d (digest length per squeeze in bits)\n", squeezedOutputLength);
			if (kb_count > 1) printf("-- e = %7lld (number of times to squeeze)\n", kb_count);
		}
		else
			printf("-- d = %7d (digest length in bits)\n",d);

		printf("-- D =      %02X (hex delimiter byte)\n", delimitedSuffix);
		if (yopt) printf("-- y = %7lld (Number of key iterations)\n", pim);
#ifdef Reference
		printf("-- R = %7d (number of rounds)\n", nrRounds);
#endif
		if (oopt) printf("-- o = %7lld (bits used for one-way function)\n", oopt);
		if (Oopt) printf("-- O = %7lld (bytes used for one-way function)\n", Oopt);
		if (xopt) printf("-- x = '%s' (key file - %d bytes)\n", KeyFileSpec, KEY_FILE_SIZE);
		if (Xopt) printf("-- X = '%s' (Initialization Vector file - %d bytes)\n", IVFileSpec, IV_FILE_SIZE);
		/* -gn selects either binary or ASCII hex output and
		 *     is used with -f; default is binary.
		 *     -g or -g0 is for binary output.
		 *     -g1 is for ASCII hex output. */
		if ( file_created ) {
			if ( !ascii_data )
				printf("-- g =       0 (binary output to file '%s')\n", outfile);
			else
				printf("-- g =       1 (ASCII output (hex) to file '%s')\n", outfile);
		}
		/* Key present. Print it as entered (hex or ASCII)
		 * only if specifically requested. */
		if (key_used && print_key_ok) {   /* -k or -K */
			if (keylen) {
				if ( key_used == 1 )
					printf("-- k = '%s' (%d bits of %d bits)\n", K, keybitlen, KEY_SIZE * 8);
				else {
					printf("-- K = '%s' (%d byte", K, keylen);
					if ( keylen > 1 )
						printf("s)\n");
					else
						printf(")\n");
				}
			}
			else
			printf("-- k =    NULL ( 0 bits of %d bits)\n", KEY_SIZE * 8);
		}

		/* IV present. Print it as entered (hex or ASCII) */
		if ( IV_used ) {   /* -j or -J */
			if ( IVlen ) {
				if (IV_used == 1)
					printf("-- j = '%s' (%d byte", IV, IVlen);
				else
					printf("-- J = '%s' (%d byte", IV, IVlen);
				if (IVlen > 1 || IVlen == 0)
					printf("s IV)\n");
				else
					printf(" IV)\n");
			}
		}

		/* print out the seed if used */
		if (seed_used) {
			printf("-- u = ");
			dlen = SEEDSIZE / 8;
			offset = 0;
			while (dlen > 0) {
				j = min (dlen, 32);
				for(i = offset; i < j + offset; i++)
					printf("%02x", rseed[i]);
				dlen -= j;
				offset += 32;
				if ( dlen > 0 )
					printf("\n--     ");
				else
					printf("\n--     (random seed - %d bytes)\n", SEEDSIZE / 8);
			}
		}

		if ( lopt )   /* number of bits specified */
			printf("-- l = %7d (bits to use of -m)\n", mBitLength);

		if (MsgPresent) {   /* if -m or -M used */
			if (MsgPresent == 1) {   /* -m */
				printf("-- m = ");
				bytes = hexmsglen>>3;
				bits = hexmsglen % 8;
			}
			else {   /* -M */
				printf("-- M = ");
				bytes = msgbytelen;
			}
			if (bytes || bits)
				printf("'%s'", Msg);   /* print the message */
			else
				printf("   NULL");
			printf(" (%d byte", bytes);
			if (bytes == 0 || bytes > 1) printf("s");
			if ( bits ) {
				printf(" + %d bit", bits);
				if ( bits > 1 )
					printf("s)\n");
				else
					printf(")\n");
			}
			else
				printf(")\n");
		}
		printf("\n");
	}
	parameters_not_printed = 0;
}

static void LoadKeccakPresets() {
/* load all presets for option N optN(). Element 0 must be present; all others
 * are optional. There may be more or less as long as PRESETS in sha3sum-config.h
 * is set correctly. If any values set here are illegal or undefined, the preset
 * used will either yield incorrect results, or more likely the program will
 * complain and the preset will be unusable. The rate is not specified as it is
 * calculated by WIDTH - C.
 */
	int s = sizeof(settings[0].desig);

			/* default */                           /* SHAKE 256 */                         /* SHA3 - 384 */
	settings[0].d     =  DEFAULT_D;             settings[3].d     =        256;             settings[6].d     =        384;
	settings[0].C     =  DEFAULT_C;             settings[3].C     =        512;             settings[6].C     =        768;
	settings[0].D     =  DEFAULT_DELIMITER;     settings[3].D     =    NIST_D1;             settings[6].D     =    NIST_D2;
	strncpy(settings[0].desig, "Default ", s);  strncpy(settings[3].desig, "SHAKE256", s);  strncpy(settings[6].desig, "SHA3-384", s);
	settings[0].R     =  DEFAULT_ROUNDS;        settings[3].R     =  DEFAULT_ROUNDS;        settings[6].R     =  DEFAULT_ROUNDS;
	strncpy(settings[0].tag, "SHA3-256", s);    strncpy(settings[3].tag, "VLO", s);         strncpy(settings[6].tag, "", s);

			/* SHAKE 128 */                         /* SHA3 - 256 */                        /* SHA3 - 512 */
	settings[1].d     =        128;             settings[4].d     =        256;             settings[7].d     =        512;
	settings[1].C     =        256;             settings[4].C     =        512;             settings[7].C     =       1024;
	settings[1].D     =    NIST_D1;             settings[4].D     =    NIST_D2;             settings[7].D     =    NIST_D2;
	strncpy(settings[1].desig, "SHAKE128", s);  strncpy(settings[4].desig, "SHA3-256", s);  strncpy(settings[7].desig, "SHA3-512", s);
	settings[1].R     =  DEFAULT_ROUNDS;        settings[4].R     =  DEFAULT_ROUNDS;        settings[7].R     =  DEFAULT_ROUNDS;
	strncpy(settings[1].tag, "VLO", s);         strncpy(settings[4].tag, "", s);            strncpy(settings[7].tag, "", s);

			/* SHA3 - 224 */                        /* KECCAK */                            /* Etherium */
	settings[2].d     =        224;             settings[5].d     =        288;             settings[8].d     =        256;
	settings[2].C     =        448;             settings[5].C     =        576;             settings[8].C     =        512;
	settings[2].D     =    NIST_D2;             settings[5].D     =  NO_SUFFIX;             settings[8].D     =   NO_SUFFIX;
	strncpy(settings[2].desig, "SHA3-224", s);  strncpy(settings[5].desig, "Keccak  ", s);  strncpy(settings[8].desig, "Etherium", s);
	settings[2].R     =  DEFAULT_ROUNDS;        settings[5].R     =  DEFAULT_ROUNDS;        settings[8].R     =  DEFAULT_ROUNDS;
	strncpy(settings[2].tag, "", s);            strncpy(settings[5].tag, "", s);            strncpy(settings[8].tag, "", s);
}

/*************************************************************************
**                             M A I N                                  **
*************************************************************************/

int main(int argc, char **argv) {
	int i;
	char encfilename[FILESPEC_SIZE];

	job_start_timer();      /* For run total */
	LoadKeccakPresets();    /* Load preset Keccak settings */

	/* Process command line options */
	if ( argc == 1 ) {
		hash_stdin();
		print_hash("-");
	}

	for (i=1;i<argc;i++) {
		print_switches = 0;	/* clear print switches flag */
		if (strlen(argv[i]) == 0) continue;
		if ( (argv[i][0] != '-') && (argv[i][0] != '+') ) {
			/* argument is filename */
			hash_file(argv[i]);
			if ( file_error == 0 ) {
				encode(encfilename,argv[i]);
				print_switches = 1;
				print_hash(encfilename);
			}
		}
		else {
			if (strlen(argv[i]) == 1) {
				hash_stdin();
				print_hash("-");
				continue;
			}

			switch ( argv[i][1] ) {	                                   /*      Options:            */
				case 'b': optb(argv[i]); print_hash(argv[i]); break;   /* hash a b bit dummy file  */
				case 'B': optB(argv[i]); print_hash(argv[i]); break;   /* hash a B byte dummy file */
				case 'c': optc(argc,argv,i); i++; break;               /* check files for changes  */
				case 'C': optC(argv[i]); break;                        /* capacity */
				case 'd': optd(argv[i]); break;                        /* digest length */
				case 'D': optD(argv[i]); break;                        /* delimited suffix */
				case 'e': opte(argv[i]); break;                        /* # of blocks to print of size -Ln */
				case 'f': optf(argc,argv,i); i++; break;               /* binary or ASCII hex output to a file */
				case 'g': optg(argv[i]); break;                        /* if zero, a binary file is created; if one, */
				case 'h':                                              /*  a ASCII hex file accept both h and H */
				case 'H': opth(); break;                               /*  to print help text */
#ifdef Reference                                                       /*  */
				case 'i': opti(argv[i]); break;                        /* level to print of intermediate values */
#else
				case 'i': printf("--W - Option -i not implemented in this version; -i ignored.\n");
						break;                                         /* wrong version for -i */
#endif
				case 'j': optj(argv[i]); break;                        /* binary IV */
				case 'J': optJ(argv[i]); break;                        /* ASCII IV */
				case 'k': optk(argv[i]); break;                        /* binary key */
				case 'K': optK(argv[i]); break;                        /* ASCII key */
				case 'l': optl(argv[i]); break;                        /* bits to use of hex message from -m */
				case 'L': optL(argv[i]); break;                        /* number of bits output per squeeze */
				case 'm': optm(argv[i]); print_hash(argv[i]); break;   /* hex message to hash */
				case 'M': optM(argv[i]); print_hash(argv[i]); break;   /* ASCII message to hash */
				case 'n': optn(argv[i]); break;                        /* select a pre-configured option by digest size */
				case 'N': optN(argv[i]); break;                        /* select a pre-configured option by capacity */
				case 'o': opto(argv[i]); break;                        /* slow n-bit one-way function (-on) */
				case 'O': optO(argv[i]); break;                        /* slow n-byte one-way function (-On) */
				case 'p': optp(); break;                               /* print input parameters */
				case 'q': optq(argc,argv,i); i += 2; break;            /* apply key stream to a file */
				case 'Q': optQ(argc,argv,i); i += 2; break;            /* apply key stream to a file using duplexing */
				case 'r': optr(argv[i]); break;                        /* rate */
#ifdef Reference
				case 'R': optR(argv[i]); break;                        /* number of rounds */
#else
				case 'R': printf("--W - Option -R not implemented in this version; -R ignored.\n");
						break;                                         /* wrong version for -R */
#endif
				case 's': opts(argv[i]); break;                        /* perform hash initialization trials */
				case 'S': optS(); break;                               /* safe to print key */
				case 't': optt(); break;                               /* print timing data summary at EOJ */
				case 'T': optT(); break;                               /* print timing data after each hash or squeeze */
				case 'u': optu(); break;                               /* generate a random seed */
				case 'v': optv(); break;                               /* print version info */
				case 'x': optx(argc,argv,i); i++; break;               /* key file */
				case 'X': optX(argc,argv,i); i++; break;               /* IV file */
				case 'y': opty(argv[i]); break;                        /* PIM */
				default:  hash_file(argv[i]);                          /* default is to try and hash the parameter */
				if ( file_error == 0 && Finalized ) {
					encode(encfilename,argv[i]);
					print_switches = 1;
					print_hash(encfilename);
					print_time();
				}
				break;
			}
		}
	}

/*************************************************************************
**             E N D   O F   J O B   P R O C E S S I N G                **
*************************************************************************/

	if ( Update_error == Success ) {
		job_end_timer(); /* set the final run time */
	}

	burn (K, KEY_SIZE * 2 + 1); /* burn it all */
	burn (binary_key, KEY_SIZE);
	burn (IV, IV_SIZE * 2 + 1);
	burn (binary_IV, IV_SIZE);
	burn (key_data, KEY_FILE_SIZE);
	burn (IV_data, IV_FILE_SIZE);
	burn (binkey, MAXSIZE / 8);
	burn (binIV, MAXSIZE / 8);
	burn (Duplex_out, WIDTH / 8);

	/* print job run total if requested */
	if ( Finalized && Update_error == Success ) {
		if ( (print_times == 2 && times_printed > 1) || print_times == 1 ) {
			bits_processed = job_bits_processed;
			absorb_calls = job_absorb_calls;
			bits_squeezed = job_bits_squeezed;
			squeeze_calls = job_squeeze_calls;
			printf("\n-- JOB TOTAL TIMING FOLLOWS --\n");
			printf("-- Total job run time ");
			double et = elapsed_time;

			if ( et ) {
				printf("= ");
				int hours = (int) (et / 3600);
				if ( hours ) {
					printf("%d hour", hours);
					if ( hours > 1 ) printf("s");
					et -= (double) hours * 3600.0;
				}

				int minutes = (int) (et / 60);
				if ( minutes ) {
					if (hours)
						printf(", ");
					printf("%d minute", minutes);
					if (minutes > 1) printf("s");
					et -= (double)(minutes) * 60.0;
				}

				if ( et ) {
					if (hours || minutes)
						printf(", ");
					printf("%.3f second", et);
					if (et != 1.0) printf("s");
				}
				printf("\n");
			}
			else
				printf("too short to measure...\n");

			eoj = 1;
			print_time();   /* print job totals if wanted */
		}

		if ( file_output ) {
			printf("-- %d file", file_output);
			if (file_output > 1)
				printf("s");
			printf(" created\n");
		}
	}

	/* Wipe the states clean */
	Keccak_HashInitialize(&hash, r, C, d, delimitedSuffix);
	Keccak_DuplexInitialize(&duplex, r, C);

	return (Update_error);
}
