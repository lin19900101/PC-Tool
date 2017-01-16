


int GenerateKeyPair( unsigned long module_length, unsigned char *N, 
					unsigned char *P, unsigned char *Q, 
					unsigned char *DP, unsigned char *DQ, unsigned char *U );
					
int RSA_Pub_Encrypt( unsigned char *outputdata, unsigned long *outputlength, 
					unsigned char *inputdata, unsigned long inputlength,
					R_RSA_PUBLIC_KEY *publicKey );

int RSA_Pri_Decrypt_CRT( unsigned char *outputdata, unsigned long *outputlength,
					unsigned char *inputdata, unsigned long inputlength,
					unsigned long module_length, unsigned char *N, unsigned char *P,unsigned char *Q,
					unsigned char *DP,unsigned char *DQ,unsigned char *U );
