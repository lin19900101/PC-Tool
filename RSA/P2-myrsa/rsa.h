/* RSA.H - header file for RSA.C
 */
/* Copyright ( C ) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#include "global_rsa.h"
#include "rsaref.h"
//��Կ����
int RSAPublicEncrypt PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long, 
    R_RSA_PUBLIC_KEY */*, R_RANDOM_STRUCT * */) );
//˽ԿCRT����
int RSAPrivateEncrypt_crt PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );
//˽ԿN-D����
int RSAPrivateEncrypt_nd PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );
//��Կ����
int RSAPublicDecrypt PROTO_LIST 
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PUBLIC_KEY * ) );
//˽ԿCRT����
int RSAPrivateDecrypt_crt PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );
//˽ԿN-D����
int RSAPrivateDecrypt_nd PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );


