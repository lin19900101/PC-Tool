#include "stdafx.h"

#ifndef OUT
#define OUT
#endif

#ifndef IN 
#define IN
#endif 
/*
    string-> hex string
call way:
    Str2Hex("yao",3,char ss[]);//here!sizeof(ss)>=2*strlen("adsdff")
Return:
    ss[]="79616F"    
Author: Red Sun
*/
void Str2Hex(IN  const char* Str,
             IN  int         Strlen,    
             OUT char* pHex
              )
{

   int  len =Strlen;
   int i=0,j=0,ascii=0;
   int highBit=0,lowBit=0;//ʮλ������λ�� 
   CString s;             //��֪��Ҫ��Ҫ�ͷ�s�ڴ档���� 
   
   //��2����Ϊת��������pHex ��������ǰ�ַ��������� 
   memset(pHex, '\0', 2*sizeof(_TCHAR)*(len)); 

   for( i=0,j=0; i< len; ++i,j+=2 )
   {
       //��tmp[0]='y',��Ӧ��ASCIIΪ0x79 
       //then result[0]='7' result[1]='9'
       highBit = (Str[i]&0x000000ff)>>4; //����ʮ�����õ���λ��7
       lowBit  = (Str[i]&0x0000000f);    //�õ���λ0~0xf 
	   s.Format("tmp[%d]=%x ",i,(Str[i]&0x000000ff));
	   
MessageBox(0,&Str[i],s,MB_OK);

       //��λ��ǰ���ȴ����λ 
       if( highBit>=0 && highBit<=9 )
       {
           pHex[j] = highBit + ('0'-0x0);  //��0x0~0x9,ת��Ϊ'0'~'9'  
           
       }else if( highBit>=0xa && highBit <= 0xf )
       {
           pHex[j] = highBit + ('a'-0xa); //��0xa~0xf,ת��Ϊ'a'~'f'      
       }else
       {
           pHex[j] =0;     
       }
       
       //��λ�ں󣬴����λ       
       if( lowBit>=0 && lowBit<=9 )
       {
           pHex[j+1] = lowBit + ('0'-0x0);    
           
       }else if( lowBit>=0xa && lowBit <= 0xf )
       {
           pHex[j+1] = lowBit + ('a'-0xa);       
       }else
       {
           pHex[j+1] =0;     
       }

       printf("%x%x ",pHex[j],pHex[j+1]);
   }//for
   pHex[j-2]='\0';
   pHex[j-1]='\0';//�����������ϣ������ӡ�ַ���ʱ����Сβ�� 

   return ;
} 

/*
    hex  string->string
call way:
    Hex2Str("79616F",6��char ss[]);//here!sizeof(ss)=strlen("adsdff")/2
Return:
    ss[]='yao'
Author: Red Sun
*/
void Hex2Str(IN  const char* pHex,
             IN  int   pHexlen,    
             OUT char* Str
              )
{

   int len = pHexlen;
   int i=0,j=0,ascii=0;
   int highBit=0,lowBit=0;//ʮλ������λ�� 
   printf("len:%d\n",len);
   //MessageBox(0,pHex,0,MB_OK);

   for( i=0,j=0; i< len; ++j,i+=2 )
   {
       //��pHex[0]='6',pHex[1]='f' ת����0x6f -> ��Ӧ���ַ�Ϊ'o' 
       //then Str[0]=0x6f--->'o'
       
       //�ȼ���Str[i]��λ 
       if( pHex[i]>='0' && pHex[i] <='9')
       {
            highBit = pHex[i] -'0';       //'0'~'9' ----> 0~9 
       }else if( pHex[i]>='a' && pHex[i]<='f' )
       {
            highBit = pHex[i] -'a' +0xa;  //'a'~'f'---->0xa~0xf    
       }
       else if( pHex[i] >='A' && pHex[i]<='F')
       {
            highBit = pHex[i] -'A' +0xa;  //'A'~'F'------>0xa~0xf   
       }else
       {
            highBit =0;     
       }
       
       //�����ַ�Str[i]��Ӧ��ʮ�����Ƶĵ�λ 
       if( pHex[i+1]>='0' && pHex[i+1] <='9')
       {
            lowBit = pHex[i+1] -'0';      //'0'~'9' ----> 0~9 
       }else if( pHex[i+1]>='a' && pHex[i+1]<='f' )
       {
            lowBit = pHex[i+1] -'a' +0xa; //'a'~'f'---->0xa~0xf      
       }
       else if( pHex[i+1] >='A' && pHex[i+1]<='F')
       {
            lowBit = pHex[i+1] -'A' +0xa; //'a'~'f'---->0xa~0xf     
       }else
       {
            lowBit =0;     
       }

       Str[j]  = (highBit<<4) + lowBit;//����д��highBit<<4+lowBit; 
       
   }//for
   Str[j-1]='\0';//��������ϣ������ӡ�ַ���ʱ����Сβ�� 
   return ;
} 
/*
 
int main(IN int argc, IN char* argv[])
{
  
   char* str="yaolixing",pHex[50]={'\0'};
   char* q=0;
   char* p=Str2Hex(str,pHex);
   printf("\n");
   for(int i=0;i< strlen(str)*2; i+=2)
   printf("%x%x  ",pHex[i]-'0',pHex[i+1]-'0');

   printf("Hex2Str:%s\n",pHex);
   q=Hex2Str(pHex,p);
   printf("\nq=%s\n",q);
   free(q);
   
   free(p);
   Pause();
   return 0;    
    
}*/
