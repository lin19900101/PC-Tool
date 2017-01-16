/* RSAREF.H - header file for RSAREF cryptographic toolkit
 */
/* Copyright ( C ) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */
#ifndef _RSAREF_H_
#define _RSAREF_H_ 1

#ifdef __cplusplus
extern "C" {
#endif
/* Message-digest algorithms.
 */
#define DA_MD2 3
#define DA_MD5 5
/* Encryption algorithms to be ored with digest algorithm in Seal and Open.
 */
#define EA_DES_CBC 1
#define EA_DES_EDE2_CBC 2
#define EA_DES_EDE3_CBC 3
#define EA_DESX_CBC 4
/* RSA key lengths.
 */
//#define MIN_RSA_MODULUS_BITS 508
//#define MAX_RSA_MODULUS_BITS 512
#define MIN_RSA_MODULUS_BITS 16
#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN ( ( MAX_RSA_MODULUS_BITS + 7 ) / 8 )
#define MAX_RSA_PRIME_BITS ( ( MAX_RSA_MODULUS_BITS + 1 ) / 2 )
#define MAX_RSA_PRIME_LEN ( ( MAX_RSA_PRIME_BITS + 7 ) / 8 )
/* Maximum lengths of encoded and encrypted content, as a function of
   content length len. Also, inverse functions.
 */
#define ENCODED_CONTENT_LEN( len ) ( 4*( len )/3 + 3 )
#define ENCRYPTED_CONTENT_LEN( len ) ENCODED_CONTENT_LEN ( ( len )+8 )
#define DECODED_CONTENT_LEN( len ) ( 3*( len )/4 + 1 )
#define DECRYPTED_CONTENT_LEN( len ) ( DECODED_CONTENT_LEN ( len ) - 1 )
/* Maximum lengths of signatures, encrypted keys, encrypted
   signatures, and message digests.
 */
#define MAX_SIGNATURE_LEN MAX_RSA_MODULUS_LEN
#define MAX_PEM_SIGNATURE_LEN ENCODED_CONTENT_LEN ( MAX_SIGNATURE_LEN )
#define MAX_ENCRYPTED_KEY_LEN MAX_RSA_MODULUS_LEN
#define MAX_PEM_ENCRYPTED_KEY_LEN ENCODED_CONTENT_LEN ( MAX_ENCRYPTED_KEY_LEN )
#define MAX_PEM_ENCRYPTED_SIGNATURE_LEN \
  ENCRYPTED_CONTENT_LEN ( MAX_SIGNATURE_LEN )
#define MAX_DIGEST_LEN 16
/* Maximum length of Diffie-Hellman parameters.
 */
#define DH_PRIME_LEN( bits ) ( ( ( bits ) + 7 ) / 8 )
/* Error codes.
 */
#define RE_CONTENT_ENCODING 0x0400
#define RE_DATA 0x0401
#define RE_DIGEST_ALGORITHM 0x0402
#define RE_ENCODING 0x0403
#define RE_KEY 0x0404
#define RE_KEY_ENCODING 0x0405
#define RE_LEN 0x0406
#define RE_MODULUS_LEN 0x0407
#define RE_NEED_RANDOM 0x0408
#define RE_PRIVATE_KEY 0x0409
#define RE_PUBLIC_KEY 0x040a
#define RE_SIGNATURE 0x040b
#define RE_SIGNATURE_ENCODING 0x040c
#define RE_ENCRYPTION_ALGORITHM 0x040d
/* Random structure.
 */
typedef struct tagR_RANDOM_STRUCT{
  unsigned long bytesNeeded;
  unsigned char state[16];
  unsigned long outputAvailable;
  unsigned char output[16];
} R_RANDOM_STRUCT;
/* RSA public and private key.
 */
typedef struct tagR_RSA_PUBLIC_KEY{
  unsigned long bits;                           /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
  unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
} R_RSA_PUBLIC_KEY;
typedef struct tagR_RSA_PRIVATE_KEY{
  unsigned long bits;                           /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
  unsigned char exponent[MAX_RSA_MODULUS_LEN];          /* private exponent */
  unsigned char prime[2][MAX_RSA_PRIME_LEN];               /* prime factors */
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];   /* exponents for CRT */
  unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
} R_RSA_PRIVATE_KEY;
/* RSA prototype key.
 */
typedef struct tagR_RSA_PROTO_KEY{
  unsigned long bits;                           /* length in bits of modulus */
  int useFermat4;                        /* public exponent ( 1 = F4, 0 = 3 ) */
} R_RSA_PROTO_KEY;

/* Random structures.
 */
int R_RandomInit  ( R_RANDOM_STRUCT * );
int R_RandomUpdate 
  ( R_RANDOM_STRUCT *, unsigned char *, unsigned long );
int R_GetRandomBytesNeeded  ( unsigned long *, R_RANDOM_STRUCT * );
void R_RandomFinal  ( R_RANDOM_STRUCT * );

/* Key-pair generation.
 */
int R_GeneratePEMKeys  ( R_RSA_PUBLIC_KEY *, R_RSA_PRIVATE_KEY *, R_RSA_PROTO_KEY *,R_RANDOM_STRUCT * );

// RSA 模幂运算
int RSAPublicBlock  
  ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PUBLIC_KEY * );
int RSAPrivateBlock  
  ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * );

//根据私钥n、d来进行计算
//2005-1-19
int RSAPrivateBlock_nd 
	( unsigned char *,unsigned long *,unsigned char *,unsigned long,R_RSA_PRIVATE_KEY * );

//RSA密钥pq 向CRT密钥转换
void  ComputePrivateKey ( R_RSA_PRIVATE_KEY *, unsigned char *,unsigned char *charq,unsigned char *chare,
	unsigned long ,	unsigned long );
	
/* Routines supplied by the implementor.
 */
void R_memset  ( POINTER, int, unsigned long );
void R_memcpy  ( POINTER, POINTER, unsigned long );
int R_memcmp  ( POINTER, POINTER, unsigned long );
#ifdef __cplusplus
}
#endif
#endif
