#ifndef __PRIME_H__
#define __PRIME_H__

/* PRIME.H - header file for PRIME.C
 */
/* Copyright ( C ) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */
int GeneratePrime PROTO_LIST
  ( ( NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned long,
    R_RANDOM_STRUCT * ) );
#endif
