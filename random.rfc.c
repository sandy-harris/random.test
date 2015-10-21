/*
 * Experimental code to replace parts of random.c
 *
 * This file is a standalone test program for things
 * I want to add to random.c. Compiling it gives an
 * executable test program, not a driver.
 *
 * Uses 128-bit hash from AES-GCM instead of 160-bit
 * SHA-1. Changing the hash also allows other changes.
 *
 * Goals:
 *
 * The main design goal was improved decoupling so that
 * heavy use of /dev/urandom does not deplete the entropy
 * pool for /dev/random. As I see it, this is the only
 * place where the current random(4) design is visibly
 * flawed.
 *
 * Another goal was simpler mixing in of additional data
 * in various places. This may help with the difficult
 * problem of timely initialisation; there have been
 * some security failures due to mis-handling of this
 * issue. These cannot be completely dealt with in the
 * driver, but we can do some things.
 *
 * I believe this code achieves both goals.
 *
 * The GCM hash:
 *
 * This sort of hash-like primitive has largely replaced
 * more complex hashes in IPsec and TLS authentication;
 * the new methods are often considerably faster and the
 * code is simpler. It therefore seemed worth trying such
 * a hash here.
 *
 * I chose the Galois field multiplication from AES-GCM
 * because it is widely used, well-analysed, and
 * considered secure. References are RFCs 4106 and 5288
 * and NIST standard SP-800-38D.
 *
 * Intel and AMD both have instructions designed to
 * make the GCM calculation faster
 * https://en.wikipedia.org/wiki/CLMUL_instruction_set
 * Those are not used in this proof-of-concept code
 *
 * https://eprint.iacr.org/2013/157.pdf discusses bugs
 * in the Open SSL version of this hash.
 *
 * Whether GCM is secure for this application needs
 * analysis. IPsec generates a 128-bit hash but uses
 * only 96 bits, which makes some attacks much harder;
 * this application uses all 128 bits. Also, the input
 * for IPsec authentication is ciphertext, which is
 * highly random with any decent cipher; input here is
 * mainly pool data which may be much less random.
 *
 * Existing random(4) code folds the 160-bit SHA-1
 * output to get an 80-bit final output; I do not
 * consider such a transform necessary here, but that
 * needs analysis too.
 *	
 * I add complications beyond the basic hash; those need
 * analysis as well.
 *
 * Differences from current driver:
 *
 * I change nothing on the input side; the whole entropy
 * collection and estimation part of existing code, as
 * applied to the input pool, are untouched.
 *
 * The hashing and output routines, though, are completely
 * replaced. The management of output pools is also changed;
 * they just count how many outputs since the last reseed,
 * as a counter-mode block cipher does, rather than trying
 * to track entropy.
 *
 * Mixing:
 *
 * Much of the mixing uses invertible functions such
 * as the pseudo-Hadamard transform or aria_mix().
 * These provably cannot reduce entropy; if they
 * did, it would not be possible to invert them.
 *
 * As in existing code, all operations putting data
 * into any pool are unidirectional; they use += or
 * ^= to mix in new data so they cannot reduce the
 * randomness of the pool, even with bad input data.
 *
 * I add an array of constants[], two for each pool,
 * for use in the hashing, and a counter[] used
 * in every output operation. All operations that
 * put new data into those are also unidirectional.
 *
 * Output dependencies
 *
 * Every output from a normal pool (input, blocking
 * or non-blocking) involves a GCM hash of pool
 * contents.
 *
 * As well as pool data, every output depends on:
 *
 *   two-128-bit entries from constants[] used
 *      in the hashing
 *   a global counter[] which is also hashed
 *
 * There is a 4th dummy pool (p->data == NULL)
 * which only hashes the counter, intended to
 * replace the MD5 code in the current driver.
 *
 * There are three functions to get 128 bits,
 * two from a specified pool p
 *
 *	get128( p, out )      may block
 *	get_or_fail( p, out ) non-blocking
 *
 * get_any( out ) tries a series of sources,
 * never blocks but does not always give a
 * high-grade result
 *
 * Tests:
 *
 * Various tests here are deliberately more general
 * than necessary; this protects against coding
 * blunders, against flukes like a cosmic ray changing
 * memory, and against misbehaviour from stressed devices
 * like an overheated router, whether the stress is just
 * natural or is part of an attack.
 *
 * For example, when a value is confidently expected
 * to be either 0 or 1, if(x==0) ... if(x==1) ...
 * is the obvious way to test it, but it is slightly
 * safer to use if(x==0) ... else ... so unexpected
 * cases can be handled. Similarly, end-of-loop tests
 * could use x == N but x >= N is slightly safer.
 *
 * The value of this is arguably negligible and certainly
 * minor, but the cost is near-zero and the behaviour
 * is identical in all expected cases. I have therefore
 * done this everywhere that I noticed it was possible.
 * It would also be possible, of course, to detect and
 * log unexpected cases, but it is not clear that this
 * would be of much value.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/*
 * all three #defines below are off by default
 * "make random.all" compiles a version with all three on
 */

/* Make more expensive but apparently safer choices */
// #define CONSERVATIVE

/* emulate a working hw rng for testing */
// #define EMULATE_HW_RNG

/*
 * make some mixing faster using 64-bit arithmetic
 *
 * NOTE: My current code does not arrange for
 * 64-bit alignment so turning this on may be
 * problematic on some architectures!
 */
// #define HAVE_64_BIT

/*
 * kernel headers define these
 * so for in-kernel use these lines can just be removed
 */
typedef uint32_t u32 ;
typedef uint64_t u64 ;
typedef unsigned char u8 ;

/*
 * file of random  initialisation data generated by gen_random_init
 * always has pools[]
 * also constants[] if USE_GCM_HASH is defined
 */
#include "random_init.h"

#ifndef USE_GCM_HASH
#error Test program needs USE_GCM_HASH defined
#endif

/*
 * To allow fractional bits to be tracked, the entropy_count field is
 * denominated in units of 1/8th bits.
 *
 * 2*(ENTROPY_SHIFT + log2(poolbits)) must <= 31, or the multiply in
 * credit_entropy_bits() needs to be 64 bits wide.
 */
#define ENTROPY_SHIFT 3
#define ENTROPY_BITS(r) ((r)->entropy_count >> ENTROPY_SHIFT)

/*
 * this will fail if someone tries to use an 8K-bit pool
 * with only 32-bit math
 */
#if( (ENTROPY_SHIFT+INPUT_POOL_SHIFT) >= 16)
#ifndef HAVE_64-BIT
#error *_SHIFT values problematic for credit_entropy_bits()
#endif
#endif

#if( (INPUT_POOL_WORDS%8) || (OUTPUT_POOL_WORDS%8) )
#error Pool size not divisible by 8, which code assumes
#endif

#if( INPUT_POOL_WORDS < 32 )
#error Input pool less than a quarter of default size
#endif

#if( INPUT_POOL_WORDS < OUTPUT_POOL_WORDS )
#error Strange pool configuration, input smalller than output
#endif

/*
 * Configuration information mostly moved to
 * gen_random_init.c which writes it to
 * random_init.h so this program gets the
 * same definitions it has.
 *
 * A few things left here.
 */
#define SEC_XFER_SIZE		512

#ifdef USE_GCM_HASH
#define EXTRACT_SIZE		16	/* bytes per GCM hash output */
#else
#define EXTRACT_SIZE		10	/* 80 bits from folded SHA-1 */
#endif

/***********************************************************************
 * Things needed for out-of-kernel testing
 * Should be removed during integration with driver
 **********************************************************************/

#ifdef EMULATE_HW_RNG
static int arch_get_random_long( u32 *x ) 
{
	*x = (u32) random() ;
	return 1 ;	
}
#else
static int arch_get_random_long( u32 *x ) 
{
	*x = 0 ;	/* just so lint won't complain */
	return 0 ;	
}
#endif

/*
 * memzero_explicit() should be used in kernel crypto
 * since gcc may optimize out memset()
 *
 * this #define is OK for testing, but not for actual use
 */
#define memzero_explicit( x, n) memset( x, 0, n )

/*
 * provide some very dumb stuff
 * so code can use kernel names for time
 */

static u32 jiffies = 0x12345678 ;

typedef	u32 ktime_t ;

static ktime_t ktime_get_real()
{
	return 0x12345678 ;
}

/*
 * Emulate spinlocks for out-of-kernel tests.
 *
 * There is not much locking in this test code, what
 * there is does not really get tested since this
 * test program is single-threaded, and I am more of
 * a cryto guy than kernel hacker so it seems likely
 * some of what is there is wrong.
 *
 * There are functions spin_lock() and spin_unlock(),
 * some new locks for new data structures, and some
 * checking for obvious blunders. However, locking
 * will almost certainly need work when this code is
 * being integrated into the driver.
 *
 * I assume throughout that only code that writes
 * to a structure needs the corresponding lock;
 * readers can do without since partially-updated
 * data would not be a problem in this use.
 */
typedef unsigned spinlock_t ;

#define SPINLOCK_UNLOCKED 0u
#define SPINLOCK_LOCKED   1u

static void spin_lock( spinlock_t *lock )
{
	if( *lock != SPINLOCK_UNLOCKED )
		fprintf( stderr, "locking error; expected unlocked\n" ) ;
	*lock = SPINLOCK_LOCKED ;
}

static void spin_unlock( spinlock_t *lock )
{
	if( *lock != SPINLOCK_LOCKED )
		fprintf( stderr, "locking error: expected locked\n" ) ; 
	*lock = SPINLOCK_UNLOCKED ;
}

/****************************************************************
 * global variables and code to initialise pool structures
 * pools[] and constants[] are declared in random_init.h
 ***************************************************************/

/*
 * reduced version of struct, OK for testing this code
 * needs integration with existing struct before actual use
 */
struct my_pool	{
	u32 *A, *B, which, count ;
	int entropy_count ;
	u32 *p, *q, *end, delta, size ;
	u32 *data, poolbits ;
	spinlock_t lock ;
	} ;

/*
 * when integrating into kernel, use real function
 * for testing, dumb emulation
 */

// static void credit_entropy_bits(struct entropy_store *r, int nbits)

static void credit_entropy_bits(struct my_pool *p, int nbits)
{
	int x ;
	x = (int) ENTROPY_BITS(p) ;
	x += nbits ;
	if( x < 0 )
		x = 0 ;
	if( x > p->poolbits )
		x = p->poolbits ;
	p->entropy_count = (((u32) x) << ENTROPY_SHIFT) ;
}

/*
 * Keep the three-pool structure -- input, blocking
 * and non-blocking -- from the current driver.
 *
 * Add a 4th dummy pool that has no pool data (p->data == NULL)
 * so it only hashes the counter.
 * This can replace the MD5 code in the existing driver.
 */
static struct my_pool input_pool, blocking_pool, nonblocking_pool, dummy_pool ;

/*
 * Start with the flag indicating that a hardware rng is present
 * so that it will always be tried.
 */
static int got_hw_rng = 1 ;

/*
 * 8 words at end of constants[] array
 * used as counter[]
 */
static u32 *counter = constants + ARRAY_WORDS ;

static void load_pool_struct( struct my_pool *p, u32 *address, u32 size, u32 delta, u32 *const_entry, u32 lock )
{
	p->A = const_entry ;
	p->B = const_entry + 4 ;

	p->which = p->count = p->entropy_count = 0 ;
	p->size = size ;
	p->poolbits = (size * 32) ;
	p->delta = delta ;
	p->lock = lock ;

	p->p = p->data = address ;

	/* if no pool data, no pointers into it */
	if( p->p == NULL )	{
		p->q = p->end = NULL ;
	}
	else	{
		p->q = p->data + size/2 ;
		p->end = p->data + size ;
	}
}

static void load_all_pools()
{
	u32 *p, *q, *r, *s, *x, *y, *z ;

	/* each pool's data is a chunk of pools[] */
	x = pools ;
	y = pools+INPUT_POOL_WORDS ;
	z = pools+INPUT_POOL_WORDS+OUTPUT_POOL_WORDS ;

	/* each pool gets 256 bits (8 words) in constants[] */
	p = constants ;
	q = constants +  8 ;
	r = constants + 16 ;
	s = constants + 24 ;	

	/* input pool starts unlocked so inputs can be accepted */
	load_pool_struct( &input_pool, x, INPUT_POOL_WORDS, 3, p, SPINLOCK_UNLOCKED ) ;

	/* start these as locked, initialisation will unlock them */
	load_pool_struct( &blocking_pool, y, OUTPUT_POOL_WORDS, 5, q, SPINLOCK_LOCKED ) ;
	load_pool_struct( &nonblocking_pool, z, OUTPUT_POOL_WORDS, 7, r, SPINLOCK_LOCKED ) ;

	load_pool_struct( &dummy_pool, NULL, 0, 0, s, SPINLOCK_UNLOCKED ) ;
}

/*****************************************************************
 * forward declarations and a few macros
 *****************************************************************/

static void init_random() ;

/* fill an output buffer from a pool */
static void loop_output( struct my_pool *, u32 *, u32 ) ;

static void count() ;
static void counter_any() ;

/* get 128 bits */
static int get_or_fail( struct my_pool *, u32 * ) ;
static void get128( struct my_pool *, u32 * ) ;
static int get_any( u32 * ) ;

/* These functions each do a unidirectional mix
 * into some data structure. They mix in 128 bits
 * at a time to give "catastrophic reseeding", and
 * all zero out the input buffer after use.
 */
static void buffer2array( struct my_pool *, u32 * ) ;
static void buffer2pool(  struct my_pool *, u32 * ) ;
static void buffer2counter( u32 * ) ;

/* hw rng functions */
static int get_hw_random( u32 * ) ;
static int load_constants() ;
static int load_input() ;

/* rotate a 32-bit word left n bits */
#define ROTL(v, n) ( ((v) << (n)) | ((v) >> (32 - (n))) )

/* common case with 128-bit buffer */
#define zero128( target )	memzero_explicit( (u8 *) target, 16 )

/*********************************************************
 * unidirectional mixing operations
 *
 * both mix 128 bits from source into target
 * two ways: xor or additions
 ********************************************************/

static inline void xor128(u32 *target, u32 *source)
{
#ifdef HAVE_64_BIT
	u64 *s, *t ;
	s = (u64 *) source ;
	t = (u64 *) target ;
	t[0] ^= s[0] ;
	t[1] ^= s[1] ;
#else
	target[0] ^= source[0] ;
	target[1] ^= source[1] ;
	target[2] ^= source[2] ;
	target[3] ^= source[3] ;
#endif
}	

/*
 * not a 128-bit addition,
 * just four 32-bit or two 64-bit
 */
static inline void add128(u32 *target, u32 *source)
{
#ifdef HAVE_64_BIT
	u64 *s, *t ;
	s = (u64 *) source ;
	t = (u64 *) target ;
	t[0] += s[0] ;
	t[1] += s[1] ;
#else
	target[0] += source[0] ;
	target[1] += source[1] ;
	target[2] += source[2] ;
	target[3] += source[3] ;
#endif
}

static inline void add256(u32 *target, u32 *source)
{
#ifdef HAVE_64_BIT
	u64 *s, *t ;
	s = (u64 *) source ;
	t = (u64 *) target ;
	t[0] += s[0] ;
	t[1] += s[1] ;
	t[2] += s[2] ;
	t[3] += s[3] ;
#else
	target[0] += source[0] ;
	target[1] += source[1] ;
	target[2] += source[2] ;
	target[3] += source[3] ;
	target[4] += source[4] ;
	target[5] += source[5] ;
	target[6] += source[6] ;
	target[7] += source[7] ;
#endif
}

/*********************************************************************
 * Two ways to mix a 128-bit buffer, one each for 256, 512 and 1024
 * These are generic functions that can mix anything the right size
 * None know anything about pools or take any locks
 *
 * All mix in place, using no external data except buffer contents
 * Any temporary storage used is cleared before returning
 *********************************************************************/

/*
 * The Aria block cipher is a Korean standard
 * Cipher home page: http://210.104.33.10/ARIA/index-e.html
 * See also RFC 5794
 *
 * This application uses only the linear transform from
 * Aria, not the whole cipher
 *
 * Mixes a 128-bit object treated as 16 bytes
 * Each output byte is the XOR of 7 input bytes
 *
 * Some caution is needed in applying this since the
 * function is its own inverse; using it twice on the
 * same data gets you right back where you started
 *
 * Version here is based on GPL source at:
 * http://www.oryx-embedded.com/doc/aria_8c_source.html
 */
static inline void aria_mix( u8 *x )
{
	u8 y[16] ;

	y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14];
	y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15];
	y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
	y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
	y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15];
	y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15];
	y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13];
	y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13];
	y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15];
	y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14];
	y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15];
	y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14];
	y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12];
	y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13];
	y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14];
	y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15];
	memcpy( x, y, 16 ) ;
	zero128( y ) ;
}

/*
 * The pseudo-Hadamard transform (PHT) can be
 * applied to any word size and any number of words
 * that is a power of two. Here for 4, 8 or 16
 * 32-bit words.
 *
 * In all cases it is invertible so it provably loses
 * no entropy, and it makes every output word depend
 * on every input word.
 *
 * conceptually, a 2-way PHT on a, b is
 *      	x = a + b
 *      	y = a + 2b
 *      	a = x
 *      	b = y
 * a better implementation is just
 *      	a += b
 *      	b += a
 *
 * Larger PHTs use multiple applications of that.
 *
 * If you have 64-bit operations and aligned
 * data structures, then these can be made
 * faster. Only pht128() and add128() need to
 * change; others just call them.
 *
 * If 32-bit arithmetic is used, then pht128()
 * pht256() and pht512() are exactly the PHT
 * on the appropriate number of 32-bit words.
 *
 * The 64-bit versions are not quite PHTs, but
 * the important properties remain. They are still
 * invertible & still make all 32-bit output words
 * depend on all input words.
 */

static void pht128( u32 *x )
{
#ifndef HAVE_64_BIT
	/*
	 * a 4-way PHT is built from 4 2-way PHTs
	 * here it is unrolled into 8 += operations
	 * each line is a two-way PHT
	 */
	x[0] += x[1] ; x[1] += x[0] ;
	x[2] += x[3] ; x[3] += x[2] ;
	x[0] += x[2] ; x[2] += x[0] ;
	x[1] += x[3] ; x[3] += x[1] ;
#else
	/*
	 * two 2-way 64-bit PHTs (4 += operations)
	 * and a swap of two 32-bit words
	 */
	u32 temp ;
	u64 *y ;
	y = (u64 *) x ;
	y[0] += y[1] ; y[1] += y[0] ;
	temp = x[1]; x[1] = x[2] ; x[2] = temp ;
	y[0] += y[1] ; y[1] += y[0] ;
#endif
}

static void pht256( u32 *x )
{
	u32 *y ;
	y = x + 4 ;

	pht128(x) ;
	pht128(y) ;

	/* 2-way PHTs across rows */
	add128( x, y ) ;
	add128( y, x ) ;
}

static void pht512( u32 *x )
{
	u32 *y ;
	y = x + 8 ;

	pht256(x) ;
	pht256(y) ;

	/* 2-way PHTs across blocks */
	add256( x, y ) ;
	add256( y, x ) ;
}

/*
 * cube_mix() is from Daniel Bernstein's Cubehash
 * It mixes 1024 bits, treated as an array of 32-bit words.
 *
 * based on Bernstein's code as distributed at
 * http://bench.cr.yp.to/supercop.html
 * He labels his code as public domain
 *
 * He has multiple versions. This is from the file
 * cubehash1632/simple where 1632 indicates his main
 * proposal (16 rounds and a 32-word state) and simple
 * indicates the simplest code. The 1632 directory also
 * has four different unrolled versions and over 20
 * versions for specific hardware. There are also
 * many other directories, so lots of options for
 * eventual optimisations. Here I just use a simple
 * one for proof-of-concept testing.
 *
 * The Cubehash algorithm has three stages:
 *
 *    1 put some constants into the array
 *      mix with this transform to get initial state
 *    2 for each input block
 *        mix input into state
 *        mix with this transform
 *    3 mix with a different transform to
 *       get an output smaller than state
 *
 * Here there is no stage 1 or 3 since the state we
 * mix is already initialised and we want output of
 * the same size. Nor is there any input data; we are
 * not hashing here.
 *
 * We just use the central transform to mix a buffer. 
 */

/*
 * This is what Bernstein uses in his main proposal
 * Arguably we need more because we lack stages 1 and 3
 * Arguably less since this not a hash; any mixing is OK
 */
#define CUBEHASH_ROUNDS 16

static void cube_mix( u32 *x )
{
  int i;
  int r;
  u32 y[16];

  for (r = 0;r < CUBEHASH_ROUNDS;++r) {
    for (i = 0;i < 16;++i) x[i + 16] += x[i];
    for (i = 0;i < 16;++i) y[i ^ 8] = x[i];
    for (i = 0;i < 16;++i) x[i] = ROTL(y[i],7);
    for (i = 0;i < 16;++i) x[i] ^= x[i + 16];
    for (i = 0;i < 16;++i) y[i ^ 2] = x[i + 16];
    for (i = 0;i < 16;++i) x[i + 16] = y[i];
    for (i = 0;i < 16;++i) x[i + 16] += x[i];
    for (i = 0;i < 16;++i) y[i ^ 4] = x[i];
    for (i = 0;i < 16;++i) x[i] = ROTL(y[i],11);
    for (i = 0;i < 16;++i) x[i] ^= x[i + 16];
    for (i = 0;i < 16;++i) y[i ^ 1] = x[i + 16];
    for (i = 0;i < 16;++i) x[i + 16] = y[i];
  }
  memzero_explicit(y, 64) ;
}

/********************************************************************
 * Code to manage the array of two 128-bit "constants" per pool
 * These are not really constants; this code changes them
 * They are treated as constants in the extract-from-pool code
 *********************************************************************/

static spinlock_t constants_lock = SPINLOCK_UNLOCKED ;

/*
 * mix one pool's constants array, two 128-bit rows
 * in place mixing, uses no external data
 * PHT + a rotation to make it nonlinear
 */
static void mix_const_p( struct my_pool *p )
{
	u32 *x ;
#ifdef HAVE_64_BIT
	u64 *y ;
	y = (u64 *) p->A ;
#endif
	x = p->A ;

	spin_lock( &constants_lock ) ;

#ifdef HAVE_64_BIT
	*y = ( ((*y)<<13) | ((*y)>>(64-13)) ) ;
#else
	*x = ROTL( *x, 5 ) ;
#endif
	pht256( x ) ;

	spin_unlock( &constants_lock ) ; 
}

/*
 * Update both constants for a pool.
 * Needs no rotations because mix_const_p() has one
 *
 * Every call to this affects every hash for that pool,
 * all future outputs from it, and all future feedback
 * into it.
 *
 * This is the preferred way to rekey a pool, rather than
 * buffer2pool() which mixes into the pool contents.
 *
 * This mixes in 128 bits of new data, so it is what the
 * Yarrow paper calls "catastrophic reseeding". It resets
 * p->count to indicate the rekeying but does not change
 * p->entropy_count.
 *
 * All buffer2*() routines zero the input data after using it
 */
static inline void buffer2array( struct my_pool *p, u32 *data )
{
	u32 *x;
	x = p->A ;
	spin_lock( &p->lock ) ;
	spin_lock( &constants_lock ) ; 
	xor128( x, data ) ;
	pht256( x ) ;
	spin_unlock( &constants_lock ) ;
	p->count = 0 ;
	spin_unlock( &p->lock ) ; 
	zero128( data ) ;
}

/*
 * mix the eight 128-bit constants[] for all pools
 * in place mixing, uses no external data
 *
 * This uses the 1024-bit transform from Bernstein's Cubehash
 * that has XOR, + and rotations so mixing is quite nonlinear
 */
static void mix_const_all( )
{
	spin_lock( &constants_lock ) ;
	cube_mix( constants ) ;
	spin_unlock( &constants_lock ) ;
}

/*
 * mix the constants[] array and both output pools
 * all in-place mixing, no external data
 */
static void big_mix()
{
	struct my_pool *n, *b ;

	n = &nonblocking_pool ;
	b = &blocking_pool ;

	(void) mix_const_all() ;

	/*
	 * mix the output pools if possible
	 * with the default value for OUTPUT_POOL_WORDS
	 * the if here always succeeds
	 *
	 * for the >32 case, only part of pool is mixed
	 * but probably enough
	 */
	if( OUTPUT_POOL_WORDS >= 32 )	{
		spin_lock( &n->lock ) ;
		cube_mix( n->data ) ;
		spin_unlock( &n->lock ) ;

		spin_lock( &b->lock ) ;
		cube_mix( b->data ) ;
		spin_unlock( &b->lock ) ;
	}
	/*
	 * the two pools combined are big enough
	 * do one mix for both
	 */
	else if( (OUTPUT_POOL_WORDS >= 16) && (n->data == b->data+OUTPUT_POOL_WORDS) )	{
		spin_lock( &n->lock ) ;
		spin_lock( &b->lock ) ;
		cube_mix( b->data ) ;
		spin_unlock( &b->lock ) ;
		spin_unlock( &n->lock ) ;
	}
	/*
	 * this should never be reached
	 * but put in some code for safety
	 */
	else if( OUTPUT_POOL_WORDS >= 8 )	{
		spin_lock( &n->lock ) ;
		pht256( n->data ) ;
		spin_unlock( &n->lock ) ;
		spin_lock( &b->lock ) ;
		pht256( b->data ) ;
		spin_unlock( &b->lock ) ;
	}
	/*
	 * This should definitely never be reached since
	 * a sanity check #if at top of program prevents it
	 * Perhaps uncomment the line below when moving code
	 * into the kernel?
	 */
	// pr_warn("random: strange value for OUTPUT_POOL_WORDS %d\n", OUTPUT_POOL_WORDS ) ;
}

/*
 * constants[] array has 10 128-bit rows
 * 8 are pool constants, last 2 counter[]
 *
 * mix the last 4 rows
 *   8 words in counter[]
 *   8 words of constants[] for dummy_pool
 *
 * no rotations needed here; count() has enough
 */
static void top_mix()
{
	u32 *x ;
	struct my_pool *d ;

	d = &dummy_pool ;
	x = d->A ;

	spin_lock( &d->lock ) ;
	spin_lock( &constants_lock ) ;
	pht512( x ) ;
	spin_unlock( &constants_lock ) ;
	spin_unlock( &d->lock ) ;
}

/**********************************************************************
 * The main hashing routines, based on authenticator code from AES-GCM
 *
 * GCM is Galois Counter Mode
 * All operations are in a Galois field with 128-bit elements
 * see http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 **********************************************************************/

static u8 abits[128], ybits[128], prodbits[256] ;

/*
 * based on Dan Bernstein's AES-GCM implementation,
 * part of CAESAR test code http://competitions.cr.yp.to/caesar.html
 *
 * Bernstein's description:
 *
 *     a = (a + x) * y in the finite field
 *     16 bytes in a
 *     xlen bytes in x; xlen <= 16; x is implicitly 0-padded
 *     16 bytes in y
 */

static void addmul(u8 *a, const u8 *x, u32 xlen, const u8 *y)
{
	int i, j;

	for (i = 0;i < xlen;++i)
		a[i] ^= x[i];
	for (i = 0;i < 128;++i)
		abits[i] = (a[i / 8] >> (7 - (i % 8))) & 1;
	for (i = 0;i < 128;++i)
		ybits[i] = (y[i / 8] >> (7 - (i % 8))) & 1;

	memzero_explicit( prodbits, 256 ) ;
	for (i = 0;i < 128;++i)
		for (j = 0;j < 128;++j)
			prodbits[i + j] ^= abits[i] & ybits[j];
	for (i = 127;i >= 0;--i)			{
		prodbits[i] ^= prodbits[i + 128];
		prodbits[i + 1] ^= prodbits[i + 128];
		prodbits[i + 2] ^= prodbits[i + 128];
		prodbits[i + 7] ^= prodbits[i + 128];
		prodbits[i + 128] ^= prodbits[i + 128];
	}

	zero128( a ) ;
	for (i = 0;i < 128;++i)
		a[i / 8] |= (prodbits[i] << (7 - (i % 8)));
}

/*
 * Bernstein's code has prodbits[], abits[] and ybits[] as locals 
 * We make them global so this function can clear them
 *
 * With them as locals we could
 * 	either clear them for every addmul() call (expensive)
 *	or not clear them at all (possible, though minor, security risk)
 * better to use globals, clear them at end of sequence
 */
static void clear_addmul()
{
	memzero_explicit( prodbits, 256 ) ;
	memzero_explicit( abits, 128 ) ;
	memzero_explicit( ybits, 128 ) ;
}

/*
 * Mix n bytes into an accumulator using addmul()
 *
 * This is a keyed hash that takes nbytes of input, a 128-bit initial value
 * and 128-bit key (the multiplier for addmul()), and gives a 128-bit output.
 *
 * This routine does not either initialise the accumulator or finalise output.
 * The expected calling sequence looks like this:
 *
 *     intialise accumulator (from some constant)
 *     call this to mix in data (another constant is multiplier)
 *     optionally, repeat call one or more times for other data 
 *     finalise output
 *
 * The main use here is against the various pools, replacing the hash
 * previously used there. This should be faster and as secure, though
 * speed needs testing & the security claim needs analysis.
 *
 * Note that it can be used with any data, and with a sequence of data
 * chunks. In AES-GCM it is run over unencrypted headers so those can
 * be authenticated along with the encrypted payload.
 *
 * Here it is run over counter[] as well as pool data so that outputs
 * depend on a global piece of state, not just on one pool.
 *
 * It might also be run over any kernel data structure that is expected
 * to be unpredictable to an enemy, giving extra entropy.
 *
 * It can also be run over anything that is expected to be different
 *
 *      on each machine (e.g. Ethernet MACs)
 *      on each boot (clock data)
 * or   on each read of /dev/urandom (process info for reader).
 *
 * Such data cannot be trusted for entropy; it may be unknown to some
 * attackers, but we cannot rely on it being unknown to all. However it
 * can still be useful in a role like that of salt in a hash; it makes
 * brute force or table-driven attacks much harder.
 */
static void mix_in( u8 *data, u32 nbytes, u8 *mul, u32 *accum)
{
	u32 len, left ;
	u8 *p ;
	for( p = data, left = nbytes ; left != 0 ; p += len, left -= len)	{
		len = (left >= 16) ? 16 : left ;
		addmul( (u8 *) accum, p, len, mul ) ;
	}
}

/*
 * Start of every output routine.
 *
 * The Schneier et al Yarrow rng design rekeys a counter mode
 * block cipher from its own output every 10 blocks, to avoid
 * giving an enemy a sequence of related values to work on.
 *
 * Here we have feedback into any non-dummy pool on every iteration,
 * changing 8 pool words every time. If the pool is 4K bits, 128 words,
 * then every word is changed after 16 iterations; in a smaller pool
 * this happens sooner. That may be all the rekeying we need, but there
 * is some mixing of the constants here to supplement it.
 *
 * The dummy pool (p->data == NULL) gets no feedback into the pool, so
 * we mix its constants more often.
 *
 * This routine never requests output from any pool to drive rekeying.
 * That overhead would be excessive in a routine that is called for
 * every output operation from any pool.
 *
 * AES-GCM authentication is
 *
 *     initialise accumulator all-zero
 *     mix in data with multiplier H
 *     xor in H before output
 *
 * Algorithm here is
 *
 *     maybe mix constants p->A and p_>B
 *     initialise accumulator from p->A
 *     mix in data with multiplier p->B
 *         counter[] for any pool
 *         pool data for non-dummy pools
 *     xor in p->B
 *
 * That finishes the first hash. For the dummy pool, we stop
 * there and use that output.
 *
 * Some constants, both primes from list at:
 * https://primes.utm.edu/lists/small/10000.txt
 *
 * ADJUST THESE FOR TUNING
 * To test, I just use the first primes > 10, 100
 *
 * FREQUENCY	how often to mix constants for most pools
 * FREQDUMMY	for dummy pool
 */

#define FREQUENCY	  101
#define FREQDUMMY	   11

static void mix_first( struct my_pool *p, u32 *accum )
{
	u32 x ;

	spin_lock( &p->lock ) ;
	x = p->count++ ;
	spin_unlock( &p->lock ) ;

	/*
	 * sometimes mix constants before using them
	 * do not zero the count
	 * only buffer2array() does that
	 */
	if( p->data != NULL)	{
		if( (x%FREQUENCY) == 0 )
			mix_const_p( p ) ;
	}
	else	{
		if( (x%FREQDUMMY) == 0 )
			mix_const_p( p ) ;
	}

	/* initialise the accumulator */
	memcpy( (u8 *) accum, (u8 *) p->A, 16 ) ;

	/* mix in the counter and update it */
	addmul( (u8 *) accum, (u8 *) counter, 16, (u8 *) p->B) ;
	count() ;

	/* for non-dummy pools, mix in pool data */
	if( p->data != NULL )
		mix_in( (u8 *) p->data, p->size, (u8 *) p->B, accum ) ;

	/*
	 * finalise result
	 * it depends on at least p->A, p->B and counter[]
	 * for non-dummy pools, on pool contents as well
	 */
	xor128( accum, p->B ) ;

	/* cleanup */
	clear_addmul() ;
	x = 0 ;
}

/*
 * Last function in mixing sequence for any of 3 real pools
 * Not used for dummy pool
 *
 * No locking needed in this function
 * Caller need not hold locks either, & should not
 *
 * First, put feedback into the pool
 *
 *   save a copy of the 1st hash's result
 *   feed the result back into pool
 *
 * Then do 2nd hash to get output different from the feedback
 *
 *   re-initialise accumulator from p->B
 *   mix in saved data with multiplier p->A
 *   xor in data to get output
 *
 * The constants are used differently in the two hashes. In
 * mix_first(), A is the initialiser and B the multiplier.
 * In the second hash here, they swap roles.
 *
 * In the first hash, the same constant is used twice, first
 * as the muiltipler in finite field multiplication then in
 * an XOR. This is exactly the way that AES-GCM uses its
 * constant H.
 *
 * AES-GCM has:    hash( data, all-0, H ) xor H
 * our 1st hash:   hash( data,   A,   B ) xor B
 * our 2nd hash:   hash( data,   B,   A ) xor data
 *
 * A well-known paper on building hashes from block ciphers,
 * pretty much the standard reference on the topic, is:
 * Preneel, Govaerts & Vandewalle
 * https://www.cosic.esat.kuleuven.be/publications/article-48.ps
 *
 * It shows that some structures resist backtracking.
 * They consider 64 possibilities and show that exactly
 * 12 of them are secure. Both hashes here use structures
 * from among that 12.
 */

static void mix_last( struct my_pool *p, u32 *accum )
{
	u32 temp[4] ;

	/*
	 * for the dummy pool, this should not be called
	 * if it is, there is nothing to do here
	 */
	if( p->data == NULL )	{
		/* UNCOMMENT WHEN MOVING TO KERNEL?
		pr_warn("random: mix_last() called for dummy pool\n" ) ;
		*/
		return ;
	}

	/*
	 * for any other pool, continue
	 * save result for use in generating output
	 */
	memcpy( temp, accum, 16 ) ;

#ifdef CONSERVATIVE
	/* shake well before using */
	aria_mix( (u8 * ) temp ) ;
	pht128( temp ) ;
#endif

	/* feed intermediate result back into pool */
	buffer2pool( p, accum ) ;

	/*
	 * Apply another hash step to the saved value in temp[]
	 * to create an output different from feedback
	 */
	memcpy( accum, p->B, 16 ) ;
	addmul( (u8 *) accum, (u8 *) temp, 16, (u8 *) p->A) ;
	xor128( accum, temp ) ;

	/* cleanup */
	clear_addmul() ;
	zero128( temp ) ;
}

/*
 * Input pool rekeys from external data and maybe hardware rng
 * Blocking pool rekeys from the input pool before every output
 * Dummy pool gets its constants changed when top_mix() is used.
 *
 * In mix_first() all pools sometimes mix their own constants
 * and in mix_last() all non-dummy pools get feedback applied
 * to their pool data. All pools are affected by the counter[]
 * and by mix_const_all().
 *
 * The only place where rekeying needs more complex management
 * is for the nonblocking pool
 *
 * The blocking pool generates only one /dev/random output
 * each time it is reseeded. It appears safe to generate
 * additional outputs to reseed the nonblocking pool; there is
 * good mixing there so blocking pool output is not exposed to
 * attack by this, except in a remarkably indirect way.
 *
 * If /dev/random is used, the blocking pool is reseeded by
 * get_block(), so if /dev/random is used often, then the
 * nonblocking pool will almost always be able to safely
 * reseed from there.
 *
 * How many outputs can we safely take from a seeded pool?
 * ======================================================
 *
 * Too large a value will be insecure, but it is not clear what
 * "too large" means here. The question has been well studied
 * for counter mode block ciphers, but the analysis does not
 * apply directly here; at best it allows sensible guesses.
 *
 * For n-bit block size the Yarrow paper shows a generic attack
 * for any counter mode block cipher after 2^(n/3) output blocks,
 * about 2^42 for 128-bit block size, and one NIST document
 * suggests an absolute upper limit of 2^48 for AES-CTR.
 *
 * Real applications generally use a much lower limit. Here I
 * think a value for SAFE_OUT around 2^16 is the largest that
 * could reasonably be considered, perhaps the prime (2^16)+1.
 *
 * However, using that seems unnecessary; a much lower value
 * is enough to effectively decouple /dev/urandom and /devrandom.
 * We want a low enough value that going over it sometimes when
 * entropy is low will not be fatal.
 *
 * Even if /dev/random is not used, the nonblocking pool can reseed
 * from the blocking pool SAFE_OUT times before it needs to reseed
 * from a hardware rng or the input pool. Since it does SAFE_OUT
 * output blocks per reseed, it can produce SAFE_OUT*SAFE_OUT blocks
 * before it needs to reseed other than from the blocking pool.
 *
 * Using primes (just because), some possibilities are:
 *
 * with SAFE_OUT =   31,     almost   1,000 blocks
 * with SAFE_OUT =  101,     over    10,000 blocks
 * with SAFE_OUT =  331,     over   100,000 blocks
 * with SAFE_OUT =  503,     over   250,000 blocks
 * with SAFE_OUT = 1009,     over 1,000,000 blocks
 * with SAFE_OUT = (2^16)+1, over      2^32 blocks
 *
 * Any sensible value for SAFE_OUT will greatly reduce load on the
 * input pool when the nonblocking pool is heavily used.
 */

#ifdef CONSERVATIVE
#define SAFE_OUT 101
#else
#define SAFE_OUT 503
#endif

/* constants to test input pool entropy level */
#ifdef CONSERVATIVE
#define E_MINIMUM	(INPUT_POOL_WORDS*12)
#define E_PLENTY	(INPUT_POOL_WORDS*28)
#else
#define E_MINIMUM	512
#define E_PLENTY	(INPUT_POOL_WORDS*24)
#endif

/*
 * try to get 128 bits from a pool
 * return 1 for success, 0 for failure
 */
static int get_or_fail( struct my_pool *p, u32 *out )
{
	int flag ;
	u32 temp[4] ;

	if( p == &input_pool )		{
		spin_lock( &p->lock ) ;
		if( (flag = (ENTROPY_BITS(p) > E_MINIMUM)) )
			credit_entropy_bits( p, -128 ) ;
		spin_unlock( &p->lock ) ;
		if( flag )		{
			mix_first( p, out ) ;
			mix_last( p, out ) ;
			return 1 ;
		}
		else	return 0 ;
	}

	if( (p == &blocking_pool) || (p == &nonblocking_pool) )	{
		/*
		 * need not lock here
		 * going slightly over SAFE_OUT is not dangerous
		 */
		if( p->count < SAFE_OUT )	{
			mix_first( p, out ) ;
			mix_last( p, out ) ;
			return 1 ;
		}
		else	return 0 ;
	}

	/*
	 * dummy pool always succeeds
	 * but may need rekeying first
	 */
	if( p == &dummy_pool)	{
		if( p->count >= SAFE_OUT )	{
			get_any( temp ) ;
			buffer2array( p, temp ) ;
		}
		mix_first( p, out ) ;
		return 1 ;
	}
	/*
	 * should never be reached. Add logging?
	 * pr_warn("random: get_or_fail() gets bad pool argument\n" ) ;
	 */
	return 0 ;
}

/*
 * get 128 bits from somewhere
 * always succeeds, but may not always give good data
 *
 * return value indicates data source
 * 1 = input, 2 = blocking, 3 = nonblocking
 * 4 = dummy, 5 = hw rng
 */
static int get_any( u32 *out )
{
	int flag ;
	struct my_pool *p ;

	/*
	 * use the input pool if it has plenty
	 * of entropy
	 *
	 * unlike get_or_fail(), this function
	 * does not test for > E_MINIMUM
	 * so it avoids depleting input entropy
	 * except when there is plenty
	 */
	p = &input_pool ;
	spin_lock( &p->lock ) ;
	if( (flag = (ENTROPY_BITS(p) > E_PLENTY)) )
		credit_entropy_bits( p, -128 ) ;
	spin_unlock( &p->lock ) ;
	if( flag )	{
		mix_first( p, out ) ;
		mix_last( p, out ) ;
		return 1 ;
	}

	/*
	 * this is likely to be the most common case
	 * & should usually succeed
	 */
	if( get_or_fail( &blocking_pool, out ) )
		return 2 ;

	/*
	 * hw rng may not be fully trusted,
	 * but it is fine as a fallback here
	 */
	if( get_hw_random( out ) )	{
		/*
		 * if we reach here, hw rng works
		 * but input pool is not close to full
		 * so try to refill it
		 */
		load_input() ;
		return 5 ;
	}

	/* reaching here should be rare; do what we can */
	if( get_or_fail( &nonblocking_pool, out ) )
		return 3 ;

	/* if all else fails, dummy pool always succeeds */
	get128( &dummy_pool, out ) ;
	return 4 ;
}

/*
 * get 128 bits from a pool
 * for input or blocking pool, this may block
 * for dummy or nonblocking, it will not
 */

static u32 rekey_flip_flop = 0 ;

static void get128( struct my_pool *p, u32 *out )
{
	u32 temp[4] ;

	/*
	 * get_or_fail( p, out ) cannot be used here
	 * pool must be rekeyed before output
	 */
	if( p == &blocking_pool )	{
		/*
		 * try non-blocking function first
		 * if it fails, use blocking function
		 */
		if( !get_or_fail( &input_pool, temp ) )
			get128( &input_pool, temp ) ;

		/*
		 * one way or the other, we have data, so reseed
		 * p->count is reset in buffer2array()
		 */
		buffer2array( p, temp ) ;

		/* produce output */
		mix_first( p, out ) ;
		mix_last( p, out ) ;
		return ;
	}

	/*
	 * for any pool except blocking
	 * see if pool is ready for output
	 * dummy pool is always ready
	 */ 
	if( get_or_fail( p, out) )	{
		return ;
	}

	/*
	 * nonblocking pool not ready
	 * rekey it, without blocking
	 */
	if( p == &nonblocking_pool )	{
		/*
		 * First choice is to rekey from blocking pool
		 * This should very often succeed
		 * else non-blocking function that always succeeds
		 */
		if( !get_or_fail(&blocking_pool, temp) )
			(void) get_any( temp ) ;
		/*
		 * one way or the other, we have data, so reseed
		 * p->count is reset in buffer2array()
		 */
		buffer2array( p, temp ) ;

		/*
		 * Do some extra mixing
		 *
		 * Rekeying is infrequent enough (once
		 * every SAFE_OUT blocks) that we can
		 * afford a somewhat expensive mix here
		 *
		 * constants[] has 10 128-bits rows
		 * 8 for pool constants, 2 for counter[]
		 *
		 * mix_const_all() mixes first 8
		 * top_mix() mixes last 4
		 * they overlap so all 10 get mixed
		 * if both are used
		 */
		if( rekey_flip_flop )	{
			/*
			 * Mix all the pool constants
			 * so the rekey affects all pools
			 * This is the only full mix except
			 * during initialisation
			 */
			mix_const_all() ;
			rekey_flip_flop = 0 ;
		}
		else	{
			/*
			 * mix counter[]
			 * and constants for dummy pool  
			 */
			top_mix() ;
			rekey_flip_flop = 1 ;
		}

		/* produce output */
		mix_first( p, out ) ;
		mix_last( p, out ) ;
		return ;
	}

	if( p == &input_pool )	{
		/* pool entropy is low, so try hw rng */
		if( !load_input() )	{
			/* no hw rng, toss in something */
			(void) get_any( temp ) ;
			buffer2pool( p, temp ) ;
		}

		/*
		 * ADD CODE HERE
		 * adapt code from current driver
		 * needs to block sometimes
		 * and deal with entropy_count
		 */
		spin_lock( &p->lock ) ;
		credit_entropy_bits( p, -128 ) ;
		spin_unlock( &p->lock ) ;

		/* produce output */
		mix_first( p, out ) ;
		mix_last( p, out ) ;
		return ;
	}
	/*
	 * should never be reached. Add logging?
	 * pr_warn("random: get128() gets bad pool argument\n" ) ;
	 */
}

/*
 * current driver has

static void extract_buf(struct entropy_store *r, __u8 *out)

 * so first cut at integration would be

static void extract_buf(struct my_pool *p, u8 *out)
{
	get128( p, (u32 *) out ) ;
}
*/

/*****************************************************************
 * loop to fill an output buffer with data
 * for input or blocking pool, this may block
 *****************************************************************/

static void loop_output( struct my_pool *p, u32 *out, u32 nbytes )
{
	u32 temp[4] ;
	int n, m ;
	u8 *x ;

	/*
	 * for pools that may block, try to avoid it
	 * fill input pool from hw rng if available
	 */
	if( got_hw_rng && ((p == &input_pool) || (p==&blocking_pool)) )
		load_input() ;

	/*
	 * Ensure that each call to this function will start
	 * a new output stream which is almost independent
	 * of previous streams.
	 *
	 * For a rationale, see the Fortuna paper by
	 * Schneier et al. They are rekeying a counter-mode
	 * block cipher, but the principle applies here. 
	 */
	counter_any() ;

	/*
	* ADD CODE HERE?
	*
	* For /dev/urandom accesses, we could mix in process
	* info for the reading process, just apply addmul()
	* to task_info struct to mix it into counter[] or
	* into the constants
	*
	* This depends on a different aspect of the system than
	* anything else in the driver, namely the order in which
	* user processes ask for data and the current state of
	* those processes.
	*
	* Except perhaps on simple embedded systems, this should
	* be hard to guess. It should be impossible to monitor
	* unless the attacker is logged into the system or has
	* left a background process running on it. Even then,
	* monitoring it would not be easy.
	*/

	for( n = nbytes, x = (u8 *) out ; n > 0 ; n -= m, x += m )	{
		m = (n >= 16) ? 16 : n ;
		get128( p, temp ) ;
		memcpy( x, (u8 *) temp, m) ;
	}
	zero128( temp ) ;
}

/******************************************************************
 * Mixing into pool data
 *
 * This routine is used only to mix data into the pool itself,
 * for feedback in mix_last()
 *
 *   Output operations from any pool use the hashing parts of
 *   mix_last(), not this code.
 *
 *   For rekeying, buffer2array() is preferred over this; change a
 *   constant rather than pool data. The effects are more easily
 *   analysed, and more general since changing a constant always
 *   affects the pool but not vice versa.
 *
 * Use this only for data known to be (or at least appear)
 * highly random
 *
 *      hardware RNG data
 *      hash output
 *      cipher output (not used here)
 *
 * Input mixing should NOT use this; existing driver code is far
 * better for low-to-medium entropy inputs. Existing code is OK
 * for high-entropy inputs as well, though it appears to have been
 * designed for the low entropy case.
 *
 * I added this in hopes it would be faster, and easier to analyze
 * in the high-entropy case. Also, using two different mixers gives
 * insurance if either has some unknown weakness.
 *******************************************************************/

/*
 * Mix a 128-bit buffer into a pool, changing 8 32-bit pool words
 * All buffer2*() routines zero the input data after using it
 *
 * This does not reset p->count; only buffer2array() does that
 * Nor does it change p->entropy_count
 *
 * Eventually this stirs the entire pool, making every pool word
 * depend both on every other pool word and on many external inputs.
 * This is the only stirring the output pools get, except during
 * initialisation.
 */
static void buffer2pool( struct my_pool *p, u32 *buff)
{
	u32 *a, *b ;
#ifdef HAVE_64_BIT
	u64 *c ;
#endif

	/* normal case, real pool */
	if( p->data != NULL )	{
		spin_lock( &p->lock ) ;
		a = p->p ;
		b = p->q ;
#ifdef HAVE_64_BIT
		c = (u64 *) a ;
		*c = ((*c) << 13) | ((*c) >> (64-13)) ;
#else
		a[0] = ROTL( a[0], 5 ) ;
#endif
		xor128( a, buff ) ;
		pht128( a ) ;
#ifdef CONSERVATIVE
		aria_mix( (u8 *) b ) ;
#endif
		/* PHTs between rows */
		add128( a, b ) ;
		add128( b, a ) ;
		/* update pointers */
		p->p += 4 ;
		if( p->p >= p->end )
			p->p = p->data ;
		p->q += 4 ;
		if( p->q >= p->end )
			p->q = p->data ;		
		spin_unlock( &p->lock ) ;
		zero128( buff ) ;
	}
	/*
	 * if called for dummy pool, which should not happen
	 * there is no pool to mix to
	 * so mix to constants instead
	 */
	else	buffer2array( p, buff ) ;
}

/*************************************************************
 *	setup routines, called once at startup 
 ************************************************************/

/*
 * existing code, here as comment for comparison
 *
 * init_std_data - initialize pool with system data
 *
 * @r: pool to initialize
 *
 * This function clears the pool's entropy count and mixes some system
 * data into the pool to prepare it for use. The pool is not cleared
 * as that can only decrease the entropy in the pool.

static void init_std_data(struct entropy_store *r)
{
	int i;
	ktime_t now = ktime_get_real();
	unsigned long rv;

	r->last_pulled = jiffies;
	mix_pool_bytes(r, &now, sizeof(now));
	for (i = r->poolinfo->poolbytes; i > 0; i -= sizeof(rv)) {
		if (!arch_get_random_seed_long(&rv) &&
		    !arch_get_random_long(&rv))
			rv = random_get_entropy();
		mix_pool_bytes(r, &rv, sizeof(rv));
	}
	mix_pool_bytes(r, utsname(), sizeof(*(utsname())));
}
*/

/*
	initialise counter & output pools

	This should not be done until there is
	enough (256 bits?) entropy in the input
	pool.

	This code does not deal with that problem!
	FIX BEFORE USING
 */

/* how many 128-bit chunks to mix into a pool */
#define HOW_MANY	4

static void init_random()
{
	u32 temp[4], *x, *y ;
	int j, limit ;
	struct my_pool *i, *b, *n, *d ;
	ktime_t now ;

	i = &input_pool ;
	b = &blocking_pool ;
	n = &nonblocking_pool ;
	d = &dummy_pool ;

	/* set up pool structs */
	load_all_pools() ;

	/*
	 * fill input pool from hardware rng if possible
	 * if that works, mix hw data into constants as well
	 */
	if( load_input() )
		(void) load_constants() ;

	/*
	 * ADD CODE HERE?
	 *
	 * If data from kernel command line is available,
	 * mix it into counter[] or input pool before doing
	 * anything else. Either way, it will then affect
	 * all future operations
	 *
	 * Simplest: XOR 256 bits into 8 words of counter[]
	 */
 
	mix_first( i, temp ) ;

	/*
	 * Existing code to get data for the input pool uses timer
	 * information. So do programs like my maxwell(8), Stephan
	 * Mueller's jitter driver or Havege. Most of my code here
	 * therefore does not use timings since that entropy is
	 * already accounted for. There are two exceptions:
	 *
	 * buffer2counter() mixes in jiffies
	 *
	 * Here timer info is added so initialisation is a bit
	 * different each time. Nowhere near enough entropy
	 * to make things secure by itself, but better than
	 * nothing.
	 */
	now = ktime_get_real() ;
	mix_in( (u8 *) &now, sizeof(now), (u8 *) i->B, temp) ;

	/*
	 * ADD CODE HERE
	 *
	 * Mix static info into temp[]
	 * things that can act as salt
	 * 
	 * These need not be unpredictable
	 * just different on different systems
	 * e.g. ethernet MAC, other hardware info.
	 *
	 * Existing code uses utsname(). That and if
	 * possible more should be added here.
	 */

	mix_last( i, temp ) ;

	/*
	 * Use that first result to re-initialise the counter
	 * This will affect all future outputs from any pool
	 *
	 * Provided enough entropy is present before this,
	 * from any of:
	 *	data in random_init.h
	 *	kernel command line
	 *	input to pool before this runs
	 * this makes the counter unknowable to an enemy
	 *
	 * All future outputs, including the ones that
	 * rekey pools below, depend on the counter
	 */
	buffer2counter( temp ) ;

	/* unlock the output pools */
	nonblocking_pool.lock = SPINLOCK_UNLOCKED ;
	blocking_pool.lock = SPINLOCK_UNLOCKED ;

	/*
	 * mix data into the output pools
	 * try to get from input pool first
	 * else from dummy pool which never blocks
	 *
	 * don't use get_any() yet; its only advantage
	 * over just using dummy pool is that it might
	 * get from output pools, but that is much more
	 * expensive and output pools are not fully
	 * initialised yet 
	 */
#ifdef CONSERVATIVE
	limit = OUTPUT_POOL_WORDS/4 ;
#else
	limit = HOW_MANY ;
#endif
	for( j = 0, x=n->data, y=b->data ; j < limit ; j++, x+=4, y+=4 )	{
		if( !get_or_fail(i, temp) )
			get128( d, temp) ;
		spin_lock( &n->lock) ;
		xor128( x, temp ) ;
		spin_unlock( &n->lock) ;
#ifdef CONSERVATIVE
		/* use different data for each pool */
		if( !get_or_fail(i, temp) )
			get128( d, temp) ;
#endif
		spin_lock( &b->lock) ;
		add128( y, temp ) ;
		spin_unlock( &b->lock) ;
	}
	/* now get_any() and constants_any() can be used */

#ifdef CONSERVATIVE
	limit = INPUT_POOL_WORDS/4 ;
#else
	limit = HOW_MANY ;
#endif
	/*
	 * refill input pool from hardware rng if possible
	 * if that works, mix hw data into constants as well
	 */
	if( load_input() )	{
		(void) load_constants() ;
	}
	else	{
		counter_any() ;
		/*
		 * mix pseudorandom bits into input pool
		 * use cheap non-blocking source, dummy pool
		 */
		for( j = 0, x=i->data ; j < limit ; j++, x+=4 )	{
			get128( d, temp ) ;
			add128( x, temp ) ;
		}
		/*
		 * mix random data into constants[]
		 * use best available data
		 */
		(void) get_any( temp ) ;
		buffer2array( i, temp );
		(void) get_any( temp ) ;
		buffer2array( n, temp );
		(void) get_any( temp ) ;
		buffer2array( b, temp );
		(void) get_any( temp ) ;
		buffer2array( d, temp );
	}
	/* Mix constants[] and both output pools */
	big_mix() ;

	/* update counter[] and constants for dummy pool */
	top_mix() ;
}

/*****************************************************************
 * 128-bit counter to mix in when hashing
 *
 * There is only one counter[] and three functions to update it,
 * count() to iterate it, buffer2counter() or counter_any()
 * to re-initialise it with a new starting value
 * 
 * mix_first() uses counter[] and calls count(), so the count both
 * affects and is affected by all output operations on any pool.
 *
 * Operations on this counter do not affect the per-pool counts
 * for any pool, neither the entropy count nor the p->count
 * iteration counter.
 *
 * One reason for including the counter is that it allows fast
 * initialisation. The very first output from the input pool is
 * used to update the counter. Once that is done, even if the
 * pools were all worthless, every output operation would still
 * have at least the strength of hash(constants, counter) which
 * is very roughly equivalent to a counter mode block cipher
 * encrypt(key,counter).
 *
 * mix_first() mixes in the counter so it affects all output from
 * any pool and all feedback into any pool. Every operation on any
 * pool changes the counter, so it automatically influences all the
 * other pools, albeit in an indirect and quite limited way.
 *
 * This can contribute to recovery after an rng state compromise.
 * Even knowing the counter value at one time an enemy cannot infer
 * the future effects unless he can predict the order of future
 * output operations, which depends on data requests from all sources.
 * Nor can he work backwards to get previous outputs unless he knows
 * the order of previous operations.
 *
 * This may provide almost no protection on a simple embedded system
 * or over a very short time span, since in those cases an enemy
 * might guess the sequence of operations or search through some
 * moderate number of possibilties. However it should be quite
 * effective for more complex systems and longer time spans. 
 ****************************************************************/

static u32 iter_count = 0 ;
static u32 loop_count = 0 ;

/*
 * 41 times 251 iterations per loop
 * gives about 10,000 outputs before auto-rekey
 */
#ifdef CONSERVATIVE
#define MAX_LOOPS 17
#else
#define MAX_LOOPS 41
#endif

/* constant from SHA-1 */
#define COUNTER_DELTA 0x67452301

static spinlock_t counter_lock = SPINLOCK_UNLOCKED ;

/*
 * Code is based on my own work in the Enchilada cipher:
 * https://aezoo.compute.dtu.dk/doku.php?id=enchilada
 * That implements a 128-bit counter in 4 32-bit words
 *
 * Here counter[] is declared as 8 words; the others
 * are used only during updates, in buffer2counter()
 *
 * Add a constant instead of just incrementing, and include some
 * other operations, so Hamming weight changes more than for a
 * simple counter. Mix +, XOR and rotation so it is nonlinear.
 *
 * This may not be strictly necessary, but a simple counter can
 * be considered safe only if you trust the crypto completely.
 * Low Hamming weight differences in inputs do allow some attacks
 * on block ciphers or hashes and the high bits of a large counter
 * that is only incremented do not change for aeons.
 *
 * The extra code here is cheap insurance.
 *
 * For discussion, see mailing list thread starting at:
 * http://www.metzdowd.com/pipermail/cryptography/2014-May/021345.html
 */

static void count(void)
{
	int flag ;
	/*
	 * There should be enough other rekeying that
	 * this is quite rare. This is just here for
	 * safety, much as IPsec rekeys after 2^32
	 * blocks if no other rekeying is done.
	 */
	spin_lock( &counter_lock ) ;
	flag = (loop_count >= MAX_LOOPS) ;
	spin_unlock( &counter_lock ) ;
	if( flag )
		counter_any() ;

	spin_lock( &counter_lock ) ;

	/*
	 * Limit the switch to < 256 cases
	 * should work with any CPU & compiler
	 *
	 * Five constants used, all primes
	 * roughly evenly spaced, around 50, 100, 150, 200, 250
	 */
	switch( iter_count )	{
		/*
		 * mix three array elements
		 * each element is used twice
		 * once on left, once on right
		 * pattern is circular
		 */
		case 47:
			counter[1] += counter[2] ;
			break ;
		case 101:
			counter[2] += counter[3] ;
			break ;
		case 197:
			counter[3] += counter[1] ;
			break ;
		/*
		 * inject counter[0] into that loop
		 * the loop and counter[0] use +=
		 * so use ^= here
		 *
		 * inject into counter[1]
		 * so case 197 starts spreading the effect
		 */
		case 149:
			counter[1] ^= counter[0] ;
			break ;
		/*
		 * restart loop
		 * throw in rotations for nonlinearity
		 */
		case 251:
			counter[1] = ROTL( counter[1], 3) ;
			counter[2] = ROTL( counter[2], 7) ;
			counter[3] = ROTL( counter[3], 13) ;
			iter_count = -1 ;
			loop_count++ ;
			break ;
		/*
		 * for 247 out of every 252 iterations
		 * the switch does nothing
		 */ 
		default:
			break ;
	}
	/*
	 * counter[0] is purely a counter
	 * nothing above affects it
	 * uses += instead of ++ to change Hamming weight more
	 *
	 * would repeat after 2^32 iterations, not a problem
	 * since the rest of counter[] changes too and 2^32
	 * will not be reached
	 */
	counter[0] += COUNTER_DELTA ;
	iter_count++ ;

	spin_unlock( &counter_lock ) ;
}

/*
 * code to set a new counter value
 *
 * All buffer2*() routines
 *    expect 128 bits of input
 *    zero the input data after using it
 */
static void buffer2counter( u32 *data )
{
	spin_lock( &counter_lock ) ;

	/*
	 * timing data is used elsewhere in driver
	 * and we do not want an expensive operation
	 * here, so use simplest thing that makes
	 * every call different
	 */
	counter[0] ^= jiffies ;

	/*
	 * mix all 8 words in counter[] array
	 * this and top_mix() are the only things
	 * that change the high 4 words
	 */
	pht256( counter ) ;

	/*
	 * input data mixed into low 4 words of counter[]
	 * which are the actual 128-bit counter
	 *
	 * high 4 words are multiplier in GCM mixing
	 * this is the only place they are used
	 */
	addmul( (u8 *) counter, (u8 *) data, 16, (u8 *) (counter+4) ) ;

	loop_count = 0 ;
	iter_count = 0 ;

	spin_unlock( &counter_lock ) ;
	zero128( data ) ;
	clear_addmul() ;
}

static void counter_any( )
{
	u32 temp[4] ;
	(void) get_any( temp ) ;
	buffer2counter( temp ) ;
}

/****************************************************************
 * Code to deal with hardware RNG, if any
 *
 * get_hw_random() just puts 128 bits from hw rng in a buffer
 *
 * load_input() makes sure that, if we have a hardware rng, then the
 * input pool is well supplied with data
 *
 * Absent an rng instruction, these functions would be the logical
 * place to add data from something else, such as a hardware rng
 * accessed via a driver rather than an instruction (Turbid, or an
 * on-board or plug-in device) or something using timing data such
 * as Havege or Stephan Mueller's jitter. There is no code for that
 * here yet.
 *
 * Both get_hw_random() and load_input() set got_hw_rng and return
 * a value for success/failure. If all arch_get_random_long() calls
 * succeed, both got_hw_rng and the return are 1; if any call fails
 * both are 0
 *
 * Code calling those functions can either check got_hw_rng and
 * avoid the call if it is 0 or just make the call unconditionally
 * and let the function set got_hw_rng. 
 ***********************************************************************/

/*
 * How much do we trust the hardware?
 * 0-32 for entropy credit per 32-bit word
 *
 * arbitrary number here for testing
 * NEEDS TO BE SET MORE CAREFULLY
 * may need #ifdef for architecture-specific value
 */
#define	TRUST32		25

/*
 * check for out-of-bounds values, allowing only values 1-31
 * a value of 0 would be senseless
 * 32 is too trusting for any real device
 */
#if (TRUST32 < 1) || (TRUST32 > 31)
#error Out-of-bounds setting for TRUST32
#endif

/*
 * fill a 128-bit buffer with hw rand data
 * only used by routines in this section
 * other code calls those, not this, since
 * the higher-level routines do more
 */
static inline int hw2buff( u32 *out )
{
	int i ;
	u32 *p ;

	for( i = 0, p = out ; i < 4 ; i++, p++ )
		if( !arch_get_random_long( p ) )
			return 0 ;
	return 1 ;
}

/* put 128 bits into a buffer, set got_hw_rng */
static int get_hw_random( u32 *out )
{
	int r ;
	r = hw2buff( out ) ;
	got_hw_rng = r ;
	return r ;
}

/* (approximately) fill the input pool with hw rng data */

static u32 *next_word = pools ;
static u32 *end_buffer = (pools+INPUT_POOL_WORDS) ;

static int load_input()
{
	struct my_pool *p ;
	u32 x, temp[4] ;
	int i, n, r, limit, e_count ;

	p = &input_pool ;

	/*
	 * deliberately somewhat imprecise calculation
	 * we need not exactly fill the pool
	 *
	 * no lock here; we are just reading values
	 * and an error will not do real harm
	 */
	n = (p->poolbits - ENTROPY_BITS(p)) / 128 ;

	/*
	 * if pool is not full
	 * loop to put data into the pool itself
	 * this does need the lock
	 */
	if( n > 0 )			{
		limit = n*4 ;
		spin_lock( &p->lock ) ;
		for( i = e_count = 0, r = 1 ; r && (i<limit) ; i++, next_word++ )	{
			if( next_word >= end_buffer )
				next_word = pools ;
			if( (r = arch_get_random_long( &x )) )	{
				*next_word ^= x ;
				e_count += TRUST32 ;
			}
		}
		credit_entropy_bits( p, e_count ) ;
		spin_unlock( &p->lock ) ;
	}			
	/*
	 * if pool is near full, change its constants
	 * no loop, just do 128 bits
	 */
	else if( (r = hw2buff(temp)) )	{
		buffer2array( p, temp ) ;
	}
	got_hw_rng = r ;
	return r ;
}

/* update all constants with data from hw rng if possible */
static int load_constants()
{
	int i, r ;
	u32 x, *p ;

	spin_lock( &constants_lock ) ;
	for( i = 0, p = constants, r = 1 ; r && (i < ARRAY_WORDS) ; i++, p++ )	{
		if( (r = arch_get_random_long( &x )) )
			*p ^= x ;
	}
	spin_unlock( &constants_lock ) ;
	x = 0 ;
	got_hw_rng = r ;
	return r ;
}

/*******************************************************************
 * minimal rather dumb test program
 * just does initialisation then prints some outputs
 ******************************************************************/

#define BUFF_WORDS 32
#define BUFF_BYTES (BUFF_WORDS<<2)

static void printbuff(u32 * p, int nwords)
{
	int i ;
	for( i = 0 ; i < nwords ; i++ )	{
		printf( "%08x", p[i] ) ;
		if( (i%8) == 7 )	(void) putchar('\n') ;
		else			(void) putchar(' ') ;
	}
	(void) putchar('\n') ;
}

int main( int argc, char **argv)
{
	u32 buffer[BUFF_WORDS] ;

#ifdef EMULATE_HW_RNG
	srandom( constants[0] ) ;
#endif

	init_random() ;
/*
	printf("Constants array at startup:\n" ) ;
	printbuff( constants, ARRAY_WORDS ) ;

	printf("Initial value of counter[]:\n" ) ;
	printbuff( counter, 8 ) ;
*/
	printf( "input pool output\n" ) ;
	loop_output( &input_pool, buffer, (u32) BUFF_BYTES) ;
	printbuff( buffer, BUFF_WORDS) ;

	printf( "blocking pool output\n" ) ;
	loop_output( &blocking_pool, buffer, (u32) BUFF_BYTES) ;
	printbuff( buffer, BUFF_WORDS) ;

	printf( "nonblocking pool output\n" ) ;
	loop_output( &nonblocking_pool, buffer, (u32) BUFF_BYTES) ;
	printbuff( buffer, BUFF_WORDS) ;

	printf( "dummy pool output\n" ) ;
	loop_output( &dummy_pool, buffer, (u32) BUFF_BYTES) ;
	printbuff( buffer, BUFF_WORDS) ;

	return 0 ;
}