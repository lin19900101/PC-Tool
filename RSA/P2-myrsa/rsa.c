/*
 本工程中主要使用了RSA的产生公私钥对、公钥加密和私钥解密功能,
 即GenerateKeyPair、和RSA_Pub_Encrypt和RSA_Pri_Decrypt_CRT两个函数。
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "stdafx.h"
#include "global_rsa.h"
#include "rsaref.h"
#include "r_random.h"
#include "nn.h"
#include "prime.h"
#include "rsa.h"
#include "string.h"

#define MYE_LEN 3
unsigned char myE[MYE_LEN]={1,0,1};

R_RANDOM_STRUCT g__randomstruct =
{
	0,
	"1",
	0,
	"1"
};

/*
函数功能：产生公私钥对
入口参数：
	module_length：密钥长度（位）
出口参数：（公开指数E固定：01 00 01）
	N：公钥模数N=PQ
	P：N的第一个因子P
	Q：N的第二个因子Q
	DP：CRT指数dP
	DQ：CRT指数dQ
	U：CRT系数qInV
*/
int GenerateKeyPair( unsigned long module_length, unsigned char *N, 
					unsigned char *P, unsigned char *Q, 
					unsigned char *DP, unsigned char *DQ, unsigned char *U )
{
	int i;
	unsigned long len;
	R_RSA_PUBLIC_KEY publickey;
	R_RSA_PRIVATE_KEY privatekey;
	R_RSA_PROTO_KEY protokey;
	int status;

	publickey.bits = module_length;
	len = module_length / 8;
	
	memset( &publickey, 0, sizeof( publickey ) );
	memset( &privatekey, 0, sizeof( privatekey ) );
	memset( &protokey, 0, sizeof( protokey ) );

	for(i=0;i<MYE_LEN;i++)
	{
		publickey.exponent[ sizeof( publickey.exponent ) - i-1 ] = myE[i];
	}
	protokey.bits = module_length;
	protokey.useFermat4 = 1;

	srand( (unsigned)time( NULL ) ); 
	for(i=0;i<16;i++)
    {
		g__randomstruct.state[i]=rand()%255;
		g__randomstruct.output[i]=rand()%255;
    }
	status = R_GeneratePEMKeys( &publickey, &privatekey, &protokey, &g__randomstruct );

	if( !status )
	{
		if( N )
		{
			memcpy( N, publickey.modulus + sizeof( publickey.modulus ) - len, len );
		}

		len /= 2;

		if( P )
		{
			memcpy( P, privatekey.prime[ 0 ] + sizeof( privatekey.prime[ 0 ] ) - len, len );
		}
		if( Q )
		{
			memcpy( Q, privatekey.prime[ 1 ] + sizeof( privatekey.prime[ 1 ] ) - len, len );
		}
		if( DP )
		{
			memcpy( DP, privatekey.primeExponent[ 0 ] + sizeof( privatekey.primeExponent[ 0 ] ) - len, len );
		}
		if( DQ )
		{
			memcpy( DQ, privatekey.primeExponent[ 1 ] + sizeof( privatekey.primeExponent[ 1 ] ) - len, len );
		}
		if( U )
		{
			memcpy( U, privatekey.coefficient + sizeof( privatekey.coefficient ) - len, len );
		}
	}

	return status;
}

/*
函数功能：公钥加密
入口参数：
	inputdata：待加密的数据
	inputlength：待加密数据长度
	publicKey：公钥结构体
		publicKey.bits：公钥长度（位）
		publicKey.modulus：公钥模数N
出口参数：
	outputdata：加密后数据
	outputlength：加密后数据长度
*/
int RSA_Pub_Encrypt( unsigned char *outputdata, unsigned long *outputlength, 
					unsigned char *inputdata, unsigned long inputlength,
					R_RSA_PUBLIC_KEY *publicKey )
{
	int i;
	unsigned long mylength;
	R_RSA_PUBLIC_KEY mypublickey;
	unsigned char myinputdata[ MAX_RSA_MODULUS_LEN ];
	int status;

	//bits
	mypublickey.bits=publicKey->bits;
	//exponent
	memset(mypublickey.exponent, 0, MAX_RSA_MODULUS_LEN);
	for(i=0;i<MYE_LEN;i++)
	{
		mypublickey.exponent[ sizeof( mypublickey.exponent ) - i-1 ] = myE[i];
	}
	//modulus
	mylength = mypublickey.bits/8;
	memset(mypublickey.modulus, 0, MAX_RSA_MODULUS_LEN);
	for(i=0;i<(int)mylength;i++)
	{
		mypublickey.modulus[MAX_RSA_MODULUS_LEN-mylength+i]=publicKey->modulus[i];
	}
	
	//input
	memset( myinputdata, 0, sizeof( myinputdata ) );
	for( i = 0; i < ( int )inputlength; i++ )
	{
		myinputdata[ i ] = inputdata[ i ];				//数据不够时在前面
	}
	
	status = RSAPublicEncrypt( outputdata, outputlength, myinputdata, mylength, &mypublickey );
	return status;
}

/*
函数功能：CRT私钥解密
入口参数：
	inputdata：待解密的数据
	inputlength：待解密数据长度
	module_length：密钥长度（位）
	N：公钥模数N=PQ
	P：N的第一个因子P
	Q：N的第二个因子Q
	DP：CRT指数dP
	DQ：CRT指数dQ
	U：CRT系数qInV
出口参数：
	outputdata：加密后数据
	outputlength：加密后数据长度
*/
int RSA_Pri_Decrypt_CRT( unsigned char *outputdata, unsigned long *outputlength,
					unsigned char *inputdata, unsigned long inputlength,unsigned long module_length, 
					unsigned char *N, unsigned char *P,unsigned char *Q,
					unsigned char *DP,unsigned char *DQ,unsigned char *U )
{
	int i, status;
	unsigned long len;
	unsigned char myin[ MAX_RSA_MODULUS_LEN ];
	R_RSA_PRIVATE_KEY privatekey;

	memset( &privatekey, 0, sizeof( privatekey ) );
	privatekey.bits = module_length;
	
	len = module_length / 8;
	for( i = 0; i < ( int )MYE_LEN; i++ )
	{
		privatekey.publicExponent[ sizeof( privatekey.publicExponent ) - MYE_LEN + i ] = myE[ i ];
	}
	for( i = 0; i < ( int )len; i++ )
	{
		privatekey.modulus[ sizeof( privatekey.modulus ) - len + i ] = N[ i ];
	}
	
	len = module_length / 16;
	for( i = 0; i < ( int )len; i++ )
	{
		privatekey.prime[ 0 ][ sizeof( privatekey.prime[ 0 ] ) - len + i ] = P[ i ];
	}
	for( i = 0; i < ( int )len; i++ )
	{
		privatekey.prime[ 1 ][ sizeof( privatekey.prime[ 1 ] ) - len + i ] = Q[ i ];
	}
	for( i = 0; i < ( int )len; i++ )
	{
		privatekey.primeExponent[ 0 ][ sizeof( privatekey.primeExponent[ 0 ] ) - len + i ] = DP[ i ];
	}
	for( i = 0; i < ( int )len; i++ )
	{
		privatekey.primeExponent[ 1 ][ sizeof( privatekey.primeExponent[ 1 ] ) - len + i ] = DQ[ i ];
	}
	for( i = 0; i < ( int )len; i++ )
	{
		privatekey.coefficient[ sizeof( privatekey.coefficient ) - len + i ] = U[ i ];
	}

	//input
	len = module_length / 8;
	memset( myin, 0, sizeof( myin ) );
	for( i = 0; i < ( int )inputlength; i++ )
	{
		myin[ i ] = inputdata[ i ];					//数据不够时在前面
	}

	status = RSAPrivateDecrypt_crt( outputdata, outputlength, myin, len, &privatekey );
	return status;
}

/* RSA public-key encryption, according to PKCS #1.
 */
int RSAPublicEncrypt(
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PUBLIC_KEY *publicKey)                       /* RSA public key */
{
  int status;
  unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
  unsigned long modulusLen;
  
  modulusLen = (publicKey->bits + 7) / 8;
  if (inputLen > modulusLen)
    return (RE_LEN);
  
  memset(pkcsBlock, 0, MAX_RSA_MODULUS_LEN);
  R_memcpy (pkcsBlock, input, inputLen);
  
  status = RSAPublicBlock(output, outputLen, pkcsBlock, inputLen, publicKey);
  R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));
  
  return (status);
}
/* RSA public-key decryption, according to PKCS #1.
 */
int RSAPublicDecrypt (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PUBLIC_KEY *publicKey)                       /* RSA public key */
{
  int status;
  unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
  unsigned long modulusLen;
  
  modulusLen = (publicKey->bits + 7) / 8;
  if (inputLen > modulusLen)
    return (RE_LEN);
  
  memset(pkcsBlock, 0, MAX_RSA_MODULUS_LEN);
  R_memcpy (pkcsBlock, input, inputLen);
  
  status = RSAPublicBlock(output, outputLen, pkcsBlock, inputLen, publicKey);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));
  
  return (status);
}
/* RSA private-key encryption, according to PKCS #1.
 */
int RSAPrivateEncrypt_crt (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PRIVATE_KEY *privateKey)                     /* RSA private key */
{
  int status;
  unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
  unsigned long modulusLen;
  
  modulusLen = (privateKey->bits + 7) / 8;
  if (inputLen > modulusLen)
    return (RE_LEN);
  
  memset(pkcsBlock,0,MAX_RSA_MODULUS_LEN);
  R_memcpy (pkcsBlock, input, inputLen);
  
  status = RSAPrivateBlock(output, outputLen, pkcsBlock, modulusLen, privateKey);
  
  R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));
  return (status);
}

/* RSA private-key encryption, according to PKCS #1.
 */
int RSAPrivateEncrypt_nd (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PRIVATE_KEY *privateKey)                     /* RSA private key */
{
  int status;
  unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
  unsigned long modulusLen;
  
  modulusLen = (privateKey->bits + 7) / 8;
  if (inputLen > modulusLen)
    return (RE_LEN);
  
  memset(pkcsBlock,0,MAX_RSA_MODULUS_LEN);
  R_memcpy (pkcsBlock, input, inputLen);
  
  status = RSAPrivateBlock_nd(output, outputLen, pkcsBlock, inputLen, privateKey);
  
  R_memset ((POINTER)pkcsBlock, 0, sizeof (pkcsBlock));
  return (status);
}
/* RSA private-key decryption, according to PKCS #1.
 */
int RSAPrivateDecrypt_nd (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PRIVATE_KEY *privateKey)                     /* RSA private key */
{
  int status;
  unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
  unsigned long modulusLen;
  
  modulusLen = (privateKey->bits + 7) / 8;
  if (inputLen > modulusLen)
    return (RE_LEN);
  
  memset(pkcsBlock,0,MAX_RSA_MODULUS_LEN);
  R_memcpy (pkcsBlock, input, inputLen);
  
  status = RSAPrivateBlock_nd(output, outputLen, pkcsBlock, inputLen, privateKey);
  
  return (status);
}

/* RSA private-key decryption, according to PKCS #1.
 */
int RSAPrivateDecrypt_crt (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PRIVATE_KEY *privateKey)                     /* RSA private key */
{
  int status;
  unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
  unsigned long modulusLen;
  
  modulusLen = (privateKey->bits + 7) / 8;
  if (inputLen > modulusLen)
    return (RE_LEN);
  
  memset(pkcsBlock,0,MAX_RSA_MODULUS_LEN);
  R_memcpy (pkcsBlock, input, inputLen);
  
  status = RSAPrivateBlock(output, outputLen, pkcsBlock, inputLen, privateKey);
  
  return (status);
}

/* Raw RSA public-key operation. Output has same length as modulus.
   Assumes inputLen < length of modulus.
   Requires input < modulus.
 */
int RSAPublicBlock (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PUBLIC_KEY *publicKey)                       /* RSA public key */
{
  NN_DIGIT c[MAX_NN_DIGITS], e[MAX_NN_DIGITS], m[MAX_NN_DIGITS],
    n[MAX_NN_DIGITS];
  unsigned long eDigits, nDigits;
  NN_Decode (m, MAX_NN_DIGITS, input, inputLen);
  NN_Decode (n, MAX_NN_DIGITS, publicKey->modulus, MAX_RSA_MODULUS_LEN);
  NN_Decode (e, MAX_NN_DIGITS, publicKey->exponent, MAX_RSA_MODULUS_LEN);
  nDigits = NN_Digits (n, MAX_NN_DIGITS);
  eDigits = NN_Digits (e, MAX_NN_DIGITS);
  
  if (NN_Cmp (m, n, nDigits) >= 0)
    return (RE_DATA);
  
  /* Compute c = m^e mod n.
   */
  NN_ModExp (c, m, e, eDigits, n, nDigits);
  *outputLen = (publicKey->bits + 7) / 8;
  NN_Encode (output, *outputLen, c, nDigits);
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)c, 0, sizeof (c));
  R_memset ((POINTER)m, 0, sizeof (m));
  return (0);
}
/* Raw RSA private-key operation. Output has same length as modulus.
   Assumes inputLen < length of modulus.
   Requires input < modulus.
 */
int RSAPrivateBlock (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PRIVATE_KEY *privateKey)                     /* RSA private key */
{
  NN_DIGIT c[MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
    dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
    mQ[MAX_NN_DIGITS], n[MAX_NN_DIGITS], p[MAX_NN_DIGITS], q[MAX_NN_DIGITS],
    qInv[MAX_NN_DIGITS], t[MAX_NN_DIGITS];
  unsigned long cDigits, nDigits, pDigits;
  
  NN_Decode (c, MAX_NN_DIGITS, input, inputLen);
  NN_Decode (n, MAX_NN_DIGITS, privateKey->modulus, MAX_RSA_MODULUS_LEN);
  NN_Decode (p, MAX_NN_DIGITS, privateKey->prime[0], MAX_RSA_PRIME_LEN);
  NN_Decode (q, MAX_NN_DIGITS, privateKey->prime[1], MAX_RSA_PRIME_LEN);
  NN_Decode 
    (dP, MAX_NN_DIGITS, privateKey->primeExponent[0], MAX_RSA_PRIME_LEN);
  NN_Decode 
    (dQ, MAX_NN_DIGITS, privateKey->primeExponent[1], MAX_RSA_PRIME_LEN);
  NN_Decode (qInv, MAX_NN_DIGITS, privateKey->coefficient, MAX_RSA_PRIME_LEN);
  cDigits = NN_Digits (c, MAX_NN_DIGITS);
  nDigits = NN_Digits (n, MAX_NN_DIGITS);
  pDigits = NN_Digits (p, MAX_NN_DIGITS);
  if (NN_Cmp (c, n, nDigits) >= 0)
    return (RE_DATA);
  
  /* Compute mP = cP^dP mod p  and  mQ = cQ^dQ mod q. (Assumes q has
     length at most pDigits, i.e., p > q.)
   */
  NN_Mod (cP, c, cDigits, p, pDigits);
  NN_Mod (cQ, c, cDigits, q, pDigits);
  NN_ModExp (mP, cP, dP, pDigits, p, pDigits);
  NN_AssignZero (mQ, nDigits);
  NN_ModExp (mQ, cQ, dQ, pDigits, q, pDigits);
  
  /* Chinese Remainder Theorem:
       m = ((((mP - mQ) mod p) * qInv) mod p) * q + mQ.
   */
  if (NN_Cmp (mP, mQ, pDigits) >= 0)
    NN_Sub (t, mP, mQ, pDigits);
  else {
    NN_Sub (t, mQ, mP, pDigits);
    NN_Sub (t, p, t, pDigits);
  }
  NN_ModMult (t, t, qInv, p, pDigits);
  NN_Mult (t, t, q, pDigits);
  NN_Add (t, t, mQ, nDigits);
  *outputLen = (privateKey->bits + 7) / 8;
  NN_Encode (output, *outputLen, t, nDigits);
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)c, 0, sizeof (c));
  R_memset ((POINTER)cP, 0, sizeof (cP));
  R_memset ((POINTER)cQ, 0, sizeof (cQ));
  R_memset ((POINTER)dP, 0, sizeof (dP));
  R_memset ((POINTER)dQ, 0, sizeof (dQ));
  R_memset ((POINTER)mP, 0, sizeof (mP));
  R_memset ((POINTER)mQ, 0, sizeof (mQ));
  R_memset ((POINTER)p, 0, sizeof (p));
  R_memset ((POINTER)q, 0, sizeof (q));
  R_memset ((POINTER)qInv, 0, sizeof (qInv));
  R_memset ((POINTER)t, 0, sizeof (t));
  return (0);
}

//根据p、q、e计算中国剩余定理的其他几个密钥系数
void  ComputePrivateKey(
	R_RSA_PRIVATE_KEY *privateKey,     
	unsigned char *charp,          					//n因子一
	unsigned char *charq,		   					//n因子二
	unsigned char *chare,		   					//公开指数,有效长度（高位）为不大于一个4字节整数
	unsigned long  plen,							//p,q数据长度(两者一致),
	unsigned long  elen)							//p,q数据长度(两者一致)
{
  NN_DIGIT d[MAX_NN_DIGITS], dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS],
    e[MAX_NN_DIGITS], n[MAX_NN_DIGITS], p[MAX_NN_DIGITS], phiN[MAX_NN_DIGITS],
    pMinus1[MAX_NN_DIGITS], q[MAX_NN_DIGITS], qInv[MAX_NN_DIGITS],
    qMinus1[MAX_NN_DIGITS], t[MAX_NN_DIGITS];

	unsigned long pDigits=(plen+NN_DIGIT_LEN-1)/NN_DIGIT_LEN ;
	unsigned long nDigits=pDigits*2;
	
	//将字符串转换为数字
	NN_Decode (p, pDigits, charp, plen);
	NN_Decode (q, pDigits, charq, plen);
	NN_Decode (e, nDigits, chare, elen);

  /* Compute n = pq, qInv = q^{-1} mod p, d = e^{-1} mod (p-1)(q-1),
     dP = d mod p-1, dQ = d mod q-1.
   */
	NN_Mult (n, p, q, pDigits);
	NN_ModInv (qInv, q, p, pDigits);

	NN_ASSIGN_DIGIT (t, 1, pDigits);
	NN_Sub (pMinus1, p, t, pDigits);
	NN_Sub (qMinus1, q, t, pDigits);
	NN_Mult (phiN, pMinus1, qMinus1, pDigits);

	NN_ModInv (d, e, phiN, nDigits);
	NN_Mod (dP, d, nDigits, pMinus1, pDigits);
	NN_Mod (dQ, d, nDigits, qMinus1, pDigits);

	//转换为字符串
	privateKey->bits =nDigits*NN_DIGIT_BITS;
	NN_Encode (privateKey->modulus, MAX_RSA_MODULUS_LEN, n, nDigits);
	NN_Encode (privateKey->publicExponent, MAX_RSA_MODULUS_LEN, e, 1);
	NN_Encode (privateKey->exponent, MAX_RSA_MODULUS_LEN, d, nDigits);
	NN_Encode (privateKey->prime[0], MAX_RSA_PRIME_LEN, p, pDigits);
	NN_Encode (privateKey->prime[1], MAX_RSA_PRIME_LEN, q, pDigits);
	NN_Encode (privateKey->primeExponent[0], MAX_RSA_PRIME_LEN, dP, pDigits);
	NN_Encode (privateKey->primeExponent[1], MAX_RSA_PRIME_LEN, dQ, pDigits);
	NN_Encode (privateKey->coefficient, MAX_RSA_PRIME_LEN, qInv, pDigits);
}

//根据私钥n、d来进行计算
int RSAPrivateBlock_nd (
unsigned char *output,                             /* output block */
unsigned long *outputLen,                          /* length of output block */
unsigned char *input,                              /* input block */
unsigned long inputLen,                            /* length of input block */
R_RSA_PRIVATE_KEY *privateKey)                     /* RSA private key */
{
  NN_DIGIT c[MAX_NN_DIGITS], d[MAX_NN_DIGITS], n[MAX_NN_DIGITS],m[MAX_NN_DIGITS];
  unsigned long cDigits, nDigits, dDigits;
  
  NN_Decode (c, MAX_NN_DIGITS, input, inputLen);
  NN_Decode (n, MAX_NN_DIGITS, privateKey->modulus, MAX_RSA_MODULUS_LEN);
  NN_Decode (d, MAX_NN_DIGITS, privateKey->exponent, MAX_RSA_MODULUS_LEN);
  
  cDigits = NN_Digits (c, MAX_NN_DIGITS);
  nDigits = NN_Digits (n, MAX_NN_DIGITS);
  dDigits = NN_Digits (d, MAX_NN_DIGITS);
  /* Compute m = c^d mod n    */
	NN_ModExp (m, c, d, dDigits, n, nDigits);

  *outputLen = (privateKey->bits + 7) / 8;
  NN_Encode (output, *outputLen, m, nDigits);
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)c, 0, sizeof (c));
  R_memset ((POINTER)d, 0, sizeof (d));
  R_memset ((POINTER)n, 0, sizeof (n));
  return (0);
}
