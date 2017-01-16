
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "global_rsa.h"
#include "rsaref.h"
#include "nn.h"
#include "digit.h"
#include "md5.h"
#include "prime.h"
#include "r_random.h"
#include "rsa.h"
#include "main.h"

#define MODULE_LENGTH_BITS		1024
#define MODULE_LENGTH_BYTES		((MODULE_LENGTH_BITS+7)/8)
#define PRIME_LENGTH_BYTES		((MODULE_LENGTH_BYTES+1)/2)
#define INPUTDATA_LENGTH		128

void main()
{
	int i;
	unsigned char myout[MODULE_LENGTH_BYTES];
	unsigned char myin[MODULE_LENGTH_BYTES];
	unsigned char mydata[INPUTDATA_LENGTH];
	unsigned long myoutlen;

	unsigned char myN[MODULE_LENGTH_BYTES];

	unsigned char myP[PRIME_LENGTH_BYTES];
	unsigned char myQ[PRIME_LENGTH_BYTES];
	unsigned char myDP[PRIME_LENGTH_BYTES];
	unsigned char myDQ[PRIME_LENGTH_BYTES];
	unsigned char myU[PRIME_LENGTH_BYTES];

	R_RSA_PUBLIC_KEY mypublickey;

	srand( (unsigned)time( NULL ) ); 
	for(i=0;i<INPUTDATA_LENGTH;i++)
    {
		mydata[i]=rand()%255;
    }

	printf("产生公私钥对...\n");

	GenerateKeyPair( MODULE_LENGTH_BITS, myN, myP, myQ, myDP, myDQ, myU );
	printf("公钥模数N:\n");
	for (i=0;i<sizeof(myN);i++)
	{
		if(myN[i]<=15&&myN[i]>=0)
			printf("0%x",myN[i]);
		else
			printf("%2x",myN[i]);
	}
	printf("\n私钥P:\n");
	for (i=0;i<sizeof(myP);i++)
	{
		if(myP[i]<=15&&myP[i]>=0)
			printf("0%x",myP[i]);
		else
			printf("%2x",myP[i]);
	}
	printf("\n私钥Q：\n");
	for (i=0;i<sizeof(myQ);i++)
	{
		if(myQ[i]<=15&&myQ[i]>=0)
			printf("0%x",myQ[i]);
		else
			printf("%2x",myQ[i]);
	}
	printf("\n私钥DP：\n");
	for (i=0;i<sizeof(myDP);i++)
	{
		if(myDP[i]<=15&&myDP[i]>=0)
			printf("0%x",myDP[i]);
		else
			printf("%2x",myDP[i]);
	}
	printf("\n私钥DQ：\n");
	for (i=0;i<sizeof(myDQ);i++)
	{
		if(myDQ[i]<=15&&myDQ[i]>=0)
			printf("0%x",myDQ[i]);
		else
			printf("%2x",myDQ[i]);
	}
	printf("\n私钥qInV：\n");
	for (i=0;i<sizeof(myU);i++)
	{
		if(myU[i]<=15&&myU[i]>=0)
			printf("0%x",myU[i]);
		else
			printf("%2x",myU[i]);
	}

	printf("\n\n公钥加密...\n输入数据:\n");
	for (i=0;i<INPUTDATA_LENGTH;i++)
	{
		if(mydata[i]<=15&&mydata[i]>=0)
			printf("0%x",mydata[i]);
		else
			printf("%2x",mydata[i]);
	}
	printf("\n");
	mypublickey.bits=MODULE_LENGTH_BITS;
	for(i=0;i<MODULE_LENGTH_BYTES;i++)
	{
		mypublickey.modulus[i]=myN[i];
	}
	memset(myout,0,sizeof(myout));
	RSA_Pub_Encrypt( myout, &myoutlen, mydata, INPUTDATA_LENGTH, &mypublickey );
	printf("公钥加密结果：\n");
	for (i=0;i<sizeof(myout);i++)
	{
		if(myout[i]<=15&&myout[i]>=0)
			printf("0%x",myout[i]);
		else
			printf("%2x",myout[i]);
	}
	printf("\n");

	for(i=0;i<MODULE_LENGTH_BYTES;i++)
	{
		myin[i]=myout[i];
	}
	printf("\n私钥解密...\n输入数据：\n");
	for (i=0;i<sizeof(myin);i++)
	{
		if(myin[i]<=15&&myin[i]>=0)
			printf("0%x",myin[i]);
		else
			printf("%2x",myin[i]);
	}
	memset(myout,0,sizeof(myout));
	RSA_Pri_Decrypt_CRT( myout, &myoutlen, myin, sizeof(myin), MODULE_LENGTH_BITS, myN, myP, myQ, myDP, myDQ, myU );
	printf("\n私钥解密结果：\n");
	for (i=0;i<sizeof(myout);i++)
	{
		if(myout[i]<=15&&myout[i]>=0)
			printf("0%x",myout[i]);
		else
			printf("%2x",myout[i]);
	}
	printf("\n私钥解密结果长度：%d",myoutlen);
	printf("\n");

	system("pause");
}