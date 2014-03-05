#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define NEED_newRV_noinc
#define NEED_sv_2pv_flags
#define NEED_sv_2pvbyte

#include "ppport.h"

//////////////////////// MD5 code ////////////////////////
// completely derived from Digest::MD5

#if BYTEORDER > 0x4321 || defined(TRUNCATE_U32)
  #define TO32(x)    ((x) &  0xFFFFffff)
  #define TRUNC32(x) ((x) &= 0xFFFFffff)
#else
  #define TO32(x)    (x)
  #define TRUNC32(x) /*nothing*/
#endif

/* The MD5 algorithm is defined in terms of little endian 32-bit
 * values.  The following macros (and functions) allow us to convert
 * between native integers and such values.
 */
#undef BYTESWAP
#ifndef U32_ALIGNMENT_REQUIRED
 #if BYTEORDER == 0x1234      /* 32-bit little endian */
  #define BYTESWAP(x) (x)     /* no-op */

 #elif BYTEORDER == 0x4321    /* 32-bit big endian */
  #define BYTESWAP(x) 	((((x)&0xFF)<<24)	\
			|(((x)>>24)&0xFF)	\
			|(((x)&0x0000FF00)<<8)	\
			|(((x)&0x00FF0000)>>8)	)
 #endif
#endif

#ifndef BYTESWAP
static void u2s(U32 u, U8* s)
{
    *s++ = (U8)(u         & 0xFF);
    *s++ = (U8)((u >>  8) & 0xFF);
    *s++ = (U8)((u >> 16) & 0xFF);
    *s   = (U8)((u >> 24) & 0xFF);
}

#define s2u(s,u) ((u) =  (U32)(*s)            |  \
                        ((U32)(*(s+1)) << 8)  |  \
                        ((U32)(*(s+2)) << 16) |  \
                        ((U32)(*(s+3)) << 24))
#endif

/* This structure keeps the current state of algorithm.
 */
typedef struct {
  U32 A, B, C, D;  /* current digest */
  U32 bytes_low;   /* counts bytes in message */
  U32 bytes_high;  /* turn it into a 64-bit counter */
  U8 buffer[128];  /* collect complete 64 byte blocks */
} MD5_CTX;

/* Padding is added at the end of the message in order to fill a
 * complete 64 byte block (- 8 bytes for the message length).  The
 * padding is also the reason the buffer in MD5_CTX have to be
 * 128 bytes.
 */
static const unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) ((((x) & ((y) ^ (z))) ^ (z)))
#define G(x, y, z) F(z, x, y)
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n) | ((x) >> (32-(n)))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, s, ac)                    \
 (a) += F ((b), (c), (d)) + (NEXTx) + (U32)(ac); \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define GG(a, b, c, d, x, s, ac)                 \
 (a) += G ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define HH(a, b, c, d, x, s, ac)                 \
 (a) += H ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define II(a, b, c, d, x, s, ac)                 \
 (a) += I ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));


static void
MD5Init(MD5_CTX *ctx)
{
  /* Start state */
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  /* message length */
  ctx->bytes_low = ctx->bytes_high = 0;
}


static void
MD5Transform(MD5_CTX* ctx, const U8* buf, STRLEN blocks)
{
#ifdef MD5_DEBUG
    static int tcount = 0;
#endif

    U32 A = ctx->A;
    U32 B = ctx->B;
    U32 C = ctx->C;
    U32 D = ctx->D;

#ifndef U32_ALIGNMENT_REQUIRED
    const U32 *x = (U32*)buf;  /* really just type casting */
#endif

    do {
	U32 a = A;
	U32 b = B;
	U32 c = C;
	U32 d = D;

#if BYTEORDER == 0x1234 && !defined(U32_ALIGNMENT_REQUIRED)
	const U32 *X = x;
        #define NEXTx  (*x++)
#else
	U32 X[16];      /* converted values, used in round 2-4 */
	U32 *uptr = X;
	U32 tmp;
 #ifdef BYTESWAP
        #define NEXTx  (tmp=*x++, *uptr++ = BYTESWAP(tmp))
 #else
        #define NEXTx  (s2u(buf,tmp), buf += 4, *uptr++ = tmp)
 #endif
#endif

#ifdef MD5_DEBUG
	if (buf == ctx->buffer)
	    fprintf(stderr,"%5d: Transform ctx->buffer", ++tcount);
	else 
	    fprintf(stderr,"%5d: Transform %p (%d)", ++tcount, buf, blocks);

	{
	    int i;
	    fprintf(stderr,"[");
	    for (i = 0; i < 16; i++) {
		fprintf(stderr,"%x,", x[i]);
	    }
	    fprintf(stderr,"]\n");
	}
#endif

	/* Round 1 */
	FF (a, b, c, d, S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, S13, 0x242070db); /* 3 */
	FF (b, c, d, a, S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d,  1, S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c,  6, S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, 11, S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a,  0, S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d,  5, S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, 10, S22,  0x2441453); /* 22 */
	GG (c, d, a, b, 15, S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a,  4, S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d,  9, S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, 14, S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b,  3, S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a,  8, S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, 13, S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c,  2, S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b,  7, S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, 12, S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d,  5, S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c,  8, S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, 11, S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, 14, S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d,  1, S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c,  4, S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b,  7, S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, 10, S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, 13, S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c,  0, S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b,  3, S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a,  6, S34,  0x4881d05); /* 44 */
	HH (a, b, c, d,  9, S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, 12, S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, 15, S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a,  2, S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d,  0, S41, 0xf4292244); /* 49 */
	II (d, a, b, c,  7, S42, 0x432aff97); /* 50 */
	II (c, d, a, b, 14, S43, 0xab9423a7); /* 51 */
	II (b, c, d, a,  5, S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, 12, S41, 0x655b59c3); /* 53 */
	II (d, a, b, c,  3, S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, 10, S43, 0xffeff47d); /* 55 */
	II (b, c, d, a,  1, S44, 0x85845dd1); /* 56 */
	II (a, b, c, d,  8, S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, 15, S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b,  6, S43, 0xa3014314); /* 59 */
	II (b, c, d, a, 13, S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d,  4, S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, 11, S42, 0xbd3af235); /* 62 */
	II (c, d, a, b,  2, S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a,  9, S44, 0xeb86d391); /* 64 */

	A += a;  TRUNC32(A);
	B += b;  TRUNC32(B);
	C += c;  TRUNC32(C);
	D += d;  TRUNC32(D);

    } while (--blocks);
    ctx->A = A;
    ctx->B = B;
    ctx->C = C;
    ctx->D = D;
}

static void
MD5Update(MD5_CTX* ctx, const U8* buf, STRLEN len)
{
    STRLEN blocks;
    STRLEN fill = ctx->bytes_low & 0x3F;

#ifdef MD5_DEBUG  
    static int ucount = 0;
    fprintf(stderr,"%5i: Update(%s, %p, %d)\n", ++ucount, ctx_dump(ctx),
	                                        buf, len);
#endif

    ctx->bytes_low += len;
    if (ctx->bytes_low < len) /* wrap around */
	ctx->bytes_high++;

    if (fill) {
	STRLEN missing = 64 - fill;
	if (len < missing) {
	    Copy(buf, ctx->buffer + fill, len, U8);
	    return;
	}
	Copy(buf, ctx->buffer + fill, missing, U8);
	MD5Transform(ctx, ctx->buffer, 1);
	buf += missing;
	len -= missing;
    }

    blocks = len >> 6;
    if (blocks)
	MD5Transform(ctx, buf, blocks);
    if ( (len &= 0x3F)) {
	Copy(buf + (blocks << 6), ctx->buffer, len, U8);
    }
}


static void
MD5Final(U8* digest, MD5_CTX *ctx)
{
    STRLEN fill = ctx->bytes_low & 0x3F;
    STRLEN padlen = (fill < 56 ? 56 : 120) - fill;
    U32 bits_low, bits_high;
#ifdef MD5_DEBUG
    fprintf(stderr,"       Final:  %s\n", ctx_dump(ctx));
#endif
    Copy(PADDING, ctx->buffer + fill, padlen, U8);
    fill += padlen;

    bits_low = ctx->bytes_low << 3;
    bits_high = (ctx->bytes_high << 3) | (ctx->bytes_low  >> 29);
#ifdef BYTESWAP
    *(U32*)(ctx->buffer + fill) = BYTESWAP(bits_low);    fill += 4;
    *(U32*)(ctx->buffer + fill) = BYTESWAP(bits_high);   fill += 4;
#else
    u2s(bits_low,  ctx->buffer + fill);   fill += 4;
    u2s(bits_high, ctx->buffer + fill);   fill += 4;
#endif

    MD5Transform(ctx, ctx->buffer, fill >> 6);
#ifdef MD5_DEBUG
    fprintf(stderr,"       Result: %s\n", ctx_dump(ctx));
#endif

#ifdef BYTESWAP
    *(U32*)digest = BYTESWAP(ctx->A);  digest += 4;
    *(U32*)digest = BYTESWAP(ctx->B);  digest += 4;
    *(U32*)digest = BYTESWAP(ctx->C);  digest += 4;
    *(U32*)digest = BYTESWAP(ctx->D);
#else
    u2s(ctx->A, digest);
    u2s(ctx->B, digest+4);
    u2s(ctx->C, digest+8);
    u2s(ctx->D, digest+12);
#endif
}

static U16 shorthash( SV * key ) {
	MD5_CTX ctx;
	int i;
	unsigned char *data;
	STRLEN len;
	unsigned char d[16];
	MD5Init(&ctx);
	data = (unsigned char *)( SvPVbyte(key, len) );
	MD5Update(&ctx, data, len);
	MD5Final(d, &ctx);
	U16 x = ( ((U16)d[0]) << 8 ) + (U16) d[1];
	//warn("got hash: %02x%02x -> %u",d[0],d[1], x);
	return x;
}

//////////////////////// MD5 code ////////////////////////

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

typedef struct {
	I32   len;
	I32   cap;
	U16 * av;
} i_array;

typedef struct {
	SV * self;
	HV * stash;
	int  replica_count;
	i_array nodes;
	HV * pos;
} ConsistentRing;

static I32 bisect(i_array * a, U16 k) {
	I32 hi = a->len - 1;
	if ( hi == -1 ) return 0;
	if ( k <= a->av[0] ) return 0;
	if ( k > a->av[hi] ) return hi+1;
	I32 lo = 0, mi = 0;
	while (lo + 1 < hi) {
		mi = lo + ( hi - lo ) / 2;
		if ( k > a->av[mi] ) {
			lo = mi;
		}
		else {
			hi = mi;
		}
	}
	return lo+1;
}

static void insort(i_array * a, U16 k) {
	if (unlikely(a->cap < a->len+1)) croak("Array overflow: %d", a->cap);
	I32 pos = bisect(a, k);
	memmove(&a->av[pos+1], &a->av[pos], sizeof(a->av[0]) * ( a->len - pos ) );
	a->av[pos] = k;
	a->len++;
}

#define svstrcmp(a,b) strcmp(SvPV_nolen(a),b)

MODULE = Hash::ConsistentRing		PACKAGE = Hash::ConsistentRing

void new(...)
	PPCODE:
		if (items < 1) croak("Usage: %s->new(...)",SvPV_nolen(ST(0)));
		ConsistentRing * self = (ConsistentRing *) safemalloc( sizeof(ConsistentRing) );
		if (unlikely(!self)) croak("Failed to allocate memory");
		memset(self,0,sizeof(ConsistentRing));
		self->stash = gv_stashpv(SvPV_nolen(ST(0)), TRUE);
		{
			SV *iv = newSViv(PTR2IV( self ));
			self->self = sv_bless(newRV_noinc (iv), self->stash);
			ST(0) = sv_2mortal(sv_bless (newRV_noinc(iv), self->stash));
		}
		int i,k,j;
		SV **key;
		AV *nodes = 0;
		self->replica_count = 100;
		for ( i=1; i < items; i=i+2) {
			if ( !svstrcmp(ST(i),"replica_count") ) {
				self->replica_count = SvUV(ST(i+1));
			}
			else
			if ( !svstrcmp(ST(i),"nodes") ) {
				if (SvROK(ST(i+1)) && SvTYPE(SvRV(ST(i+1))) == SVt_PVAV) {
					nodes = (AV *) SvRV( ST(i+1) );
				} else {
					croak("nodes must be arrayref, but got %s", SvPV_nolen(ST(i+1)));
				}
			}
			else {
				croak("Uknown option '%s'", SvPV_nolen(ST(i)));
			}
		}
		
		self->nodes.av = safemalloc( self->replica_count * (1+av_len(nodes)) * sizeof( self->nodes.av[0] ) );
		if (unlikely(!self->nodes.av)) croak("Failed to allocate memory");
		self->nodes.cap = self->replica_count * (1+av_len(nodes));
		
		self->pos = newHV();
		
		for ( i = 0; i <= av_len( nodes ); i++ ) {
			key = av_fetch( nodes, i, 0 );
			AV *node = (AV *) SvRV( *key );
			for ( k = 1; k <= self->replica_count; k++) {
				SV *hashkey = sv_2mortal(newSVpvf("('%s', '%s'):%d", SvPV_nolen( *av_fetch(node,0, 0) ), SvPV_nolen( *av_fetch(node,1, 0) ), k));
				U16 kv = shorthash(hashkey);
				while (1) {
					if (unlikely(hv_exists(self->pos,(char *)&kv,sizeof(kv)))) {
						kv++;
					}
					else {
						hv_store(self->pos,(char *)&kv, sizeof(kv), SvREFCNT_inc( *key ), 0);
						break;
					}
				}
				insort( &self->nodes, kv );
				/*
				warn("node: %d : %s -> %d",i, SvPV_nolen(hashkey), kv);
				for (j=0;j<self->nodes.len;j++) {
					printf("%d, ",self->nodes.av[j]);
				}
				printf("\n");
				*/
			}
		}
		XSRETURN(1);

void DESTROY(SV *this)
	PPCODE:
		register ConsistentRing *self = ( ConsistentRing * ) SvUV( SvRV( ST(0) ) );
		if (self->nodes.cap > 0) {
			safefree(self->nodes.av);
			self->nodes.cap = 0;
		}
		if (self->pos) SvREFCNT_dec(self->pos);
		if (self->self && SvOK(self->self) && SvOK( SvRV(self->self) )) {
			SvREFCNT_inc(SvRV(self->self));
			SvREFCNT_dec(self->self);
		}
		safefree(self);
		XSRETURN_UNDEF;

void get (SV *this, SV * key)
	PPCODE:
		register ConsistentRing *self = ( ConsistentRing * ) SvUV( SvRV( ST(0) ) );
		U16 kv = shorthash(key);
		U16 idx = bisect( &self->nodes, kv ) % self->nodes.len;
		//U16 lst = ( idx + self->nodes.len - 1 ) % self->nodes.len;
		U16 pos = self->nodes.av[idx];
		SV **node = hv_fetch(self->pos, (char *)&pos, sizeof(pos), 0 );
		ST(0) = *node;
		//ST(0) = sv_2mortal(newRV_inc( (SV *) SvRV(*node) ));
		XSRETURN(1);
