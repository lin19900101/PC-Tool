/* RSA.H - header file for RSA.C
 */
/* Copyright ( C ) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#include "global_rsa.h"
#include "rsaref.h"
//π´‘øº”√‹
int RSAPublicEncrypt PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long, 
    R_RSA_PUBLIC_KEY */*, R_RANDOM_STRUCT * */) );
//ÀΩ‘øCRTº”√‹
int RSAPrivateEncrypt_crt PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );
//ÀΩ‘øN-Dº”√‹
int RSAPrivateEncrypt_nd PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );
//π´‘øΩ‚√‹
int RSAPublicDecrypt PROTO_LIST 
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PUBLIC_KEY * ) );
//ÀΩ‘øCRTΩ‚√‹
int RSAPrivateDecrypt_crt PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );
//ÀΩ‘øN-DΩ‚√‹
int RSAPrivateDecrypt_nd PROTO_LIST
  ( ( unsigned char *, unsigned long *, unsigned char *, unsigned long,
    R_RSA_PRIVATE_KEY * ) );


