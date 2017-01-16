/*
*/
#include "stdafx.h"
#include "global_rsa.h"
#include "rsaref.h"
#include "string.h"

void R_memset (
POINTER output,                                             /* output block */
int value,                                                         /* value */
unsigned long len)                                        /* length of block */
{
  if (len)
    memset (output, value, len);
}
void R_memcpy (
POINTER output,                                             /* output block */
POINTER input,                                               /* input block */
unsigned long len)                                       /* length of blocks */
{
  if (len)
    memcpy (output, input, len);
}
int R_memcmp (
POINTER firstBlock,                                          /* first block */
POINTER secondBlock,                                        /* second block */
unsigned long len)                                       /* length of blocks */
{
  if (len)
    return (memcmp (firstBlock, secondBlock, len));
  else
    return (0);
}
