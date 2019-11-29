/* SPDX-License-Identifier: GPL-2.0-only AND GPL-CC-1.0 */
/*
 * Module: sha3sum-config.h     V1.x    Nov 2019     Jim McDevitt
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

#ifndef KECCAK_SETTINGS_H_S
  #define KECCAK_SETTINGS_H_S

/* This is for mingw on windows */
/*
#ifndef __mingw__
  #define  __mingw__
#endif
*/

/* Use this for Linux */
#ifndef __linux__
  #define  __linux__
#endif

/*************************************************************************
**      S H A 3 S U M   C O N F I G U R A T I O N   S E C T I O N       **
*************************************************************************/

/* Constants for Keccak */
#define WIDTH                       1600    /* width of state (bits) * DO NOT CHANGE */
#define DEFAULT_C                    512    /* default capacity (bits) */
#define DEFAULT_R                   1088    /* default rate (bits) */
#define DEFAULT_D                    256    /* default digest length (bits) */
#define DEFAULT_ROUNDS                24    /* default number of rounds (for reference version) */
#define NIST_D1                     0x1F    /* NIST domain separator #1 */
#define NIST_D2                     0x06    /* NIST domain separator #2 */
#define QH_DS                       0x13    /* delimiter for quick hash ONLY. This constant reserved from any other use */
#define NO_SUFFIX                   0x01    /* used for Etherium */
#define DEFAULT_DELIMITER        NIST_D2    /* default delimiter (1 byte), diversifier, or domain separator or ... */
#define MAXROUNDS                     72    /* maximum number of rounds - see optR() */
#define MAXSIZE                    16384    /* maximum length in bits for all parameters (8192 minimum) */
#define DEFAULT_SQUEEZE             8192    /* default size to squeeze (bits) */
#define KEY_SIZE                      64    /* key size in bytes */
#define KEY_FILE_SIZE               1024    /* maximum bytes to read from key file */
#define IV_SIZE                     1024    /* maximum initialization vector (IV) size in bytes */
#define IV_FILE_SIZE                1024    /* maximum bytes to read from IV file */
#define MSG_SIZE                    1024    /* maximum binary message size in bytes */
#define SEEDSIZE                   WIDTH    /* size of seed in bits (-u) */
#define SEED_HASH_COUNT                3    /* initial number of times to poll the O/S for random data during init */
#define INJECTION_THRESHOLD       100000    /* number of bytes processed duplexing to re-seed the sponge */
#define PRESETS                        9    /* number of presets LoadKeccakPresets() */
#define FILESPEC_SIZE               1500    /* size of file spec buffer (bytes) */
#define DISK_BLOCK_SIZE             1024    /* minimum number of bytes to read each disk access - multiple of 8 */
#define KEY_ITERATIONS            100000    /* number of times to re-hash the key ( >= than 10000) */

/*************************************************************************
**      E N D   O F   C O N F I G U R A T I O N   S E C T I O N         **
*************************************************************************/

/* Check configuration parameters if sane. If not, compilation should bomb. */
#if ( WIDTH != 1600 )
  #error "Keccak.c Fatal error: unsupported state width"
#elif ( DEFAULT_R + DEFAULT_C != WIDTH )
  #error "Keccak.c Fatal error: DEFAULT_R + DEFAULT_C must = WIDTH"

#elif ((DEFAULT_C < 0 ) || (DEFAULT_C > WIDTH-16))
  #error "Keccak.c Fatal error: 0 <= default capacity <= WIDTH - 16"
#elif ((DEFAULT_C % 8) != 0)
  #error "Keccak.c Fatal error: default capacity must be a multiple of 8"

#elif ((DEFAULT_R < 16 ) || (DEFAULT_R > WIDTH))
  #error "Keccak.c Fatal error: 16 <= default rate <= WIDTH"

#elif ((DEFAULT_D < 8 ) || (DEFAULT_D > DEFAULT_R))
  #error "Keccak.c Fatal error: 8 <= digest size <= DEFAULT_R"
#elif ( DEFAULT_D > MAXSIZE )
  #error "Keccak.c Fatal error: DEFAULT_D <= MAXSIZE"

#elif ( MAXROUNDS < 1 )
  #error "Keccak.c Fatal error: MAXROUNDS must be at least 1"
#elif ((DEFAULT_ROUNDS < 1 ) || (DEFAULT_ROUNDS > MAXROUNDS))
  #error "Keccak.c Fatal error: 1 <= DEFAULT_ROUNDS <= MAXROUNDS"

#elif ((DEFAULT_DELIMITER < 0x01 ) || (DEFAULT_DELIMITER > 0xff))
  #error "Keccak.c Fatal error: 0x01 <= DEFAULT_DELIMITER <= 0xff"
#elif (DEFAULT_DELIMITER == QH_DS )
  #error "Keccak.c Fatal error: default domain must differ from QH_DS"

#elif ( MAXSIZE < 8192 )
  #error "Keccak.c Fatal error: MAXSIZE must be at least the rate"
#elif ((MAXSIZE % 64) != 0)
  #error "Keccak.c Fatal error: MAXSIZE must be a multiple of 64"

#elif ((DEFAULT_SQUEEZE < 8 ) || (DEFAULT_SQUEEZE > MAXSIZE))
  #error "Keccak.c Fatal error: 8 <= DEFAULT_SQUEEZE <= MAXSIZE"
#elif ((DEFAULT_SQUEEZE % 8) != 0)
  #error "Keccak.c Fatal error: DEFAULT_SQUEEZE must be a multiple of 8"

#elif ((IV_SIZE % 8) != 0)
  #error "Keccak.c Fatal error: IV_SIZE must be a multiple of 8"
#elif ( IV_SIZE < 8 || IV_SIZE > MAXSIZE )
  #error "Keccak.c Fatal error: 8 <= IV_SIZE <= MAXSIZE"

#elif ((IV_FILE_SIZE % 8) != 0)
  #error "Keccak.c Fatal error: IV_FILE_SIZE must be a multiple of 8"
#elif ( IV_FILE_SIZE < 8 || IV_FILE_SIZE > MAXSIZE )
  #error "Keccak.c Fatal error: 8 <= IV_FILE_SIZE <= MAXSIZE"

#elif ((KEY_SIZE % 8) != 0)
  #error "Keccak.c Fatal error: Key size must be a multiple of 8"
#elif ( KEY_SIZE < 8 || KEY_SIZE > MAXSIZE )
  #error "Keccak.c Fatal error: 8 <= Key size <= MAXSIZE"

#elif ((KEY_FILE_SIZE % 8) != 0)
  #error "Keccak.c Fatal error: Key File Bytes must be a multiple of 8"
#elif ( KEY_FILE_SIZE < 8 || KEY_FILE_SIZE > MAXSIZE )
  #error "Keccak.c Fatal error: 8 <= Key File Bytes <= MAXSIZE"

#elif ( SEEDSIZE < (KEY_SIZE * 8) || SEEDSIZE > WIDTH )
  #error "Keccak.c Fatal error: Key size <= Seed Size <= WIDTH"
#elif ((SEEDSIZE % 8) != 0)
  #error "Keccak.c Fatal error: seed size must be a multiple of 8"

#elif ((NIST_D1 < 0x01 ) || (NIST_D1 > 0xff))
  #error "Keccak.c Fatal error: 0x01 <= NIST_D1 <= 0xff"
#elif ((NIST_D2 < 0x01 ) || (NIST_D2 > 0xff))
  #error "Keccak.c Fatal error: 0x01 <= NIST_D2 <= 0xff"

#elif (QH_DS < 0x01  || QH_DS > 0xff || QH_DS == NIST_D1 || QH_DS == NIST_D2)
  #error "Keccak.c Fatal error: 0x01 <= QH_DS <= 0xff or same as NIST. Must be unique."

#elif ( SEED_HASH_COUNT < 1 || SEED_HASH_COUNT > 5)
  #error "Keccak.c Fatal error: SEED_HASH_COUNT must be at least 1 and no more than 5"
#elif ( INJECTION_THRESHOLD < 1 )
  #error "Keccak.c Fatal error: INJECTION_THRESHOLD < 1"
#elif ( KEY_ITERATIONS < 10000 )
  #error "Keccak.c Fatal error: KEY_ITERATIONS < 10000"

#elif ( PRESETS < 1 )
  #error "Keccak.c Fatal error: PRESETS must be at least 1 (default settings is element 0)"

#elif ( FILESPEC_SIZE < 50 )
  #error "Keccak.c Fatal error: File spec buffers should be at least 50 bytes in length."
#elif ((DISK_BLOCK_SIZE % 8) != 0 || DISK_BLOCK_SIZE <= 0)
  #error "Keccak.c Fatal error: DISK_BLOCK_SIZE must be a multiple of 8 and > 0"
#endif

/*************************************************************************
**               E N D   O F   S A N I T Y   C H E C K                  **
*************************************************************************/

#endif /* KECCAK_SETTINGS_H_S */
