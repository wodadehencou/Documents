

#include <stdio.h>
#include <process.h>
#include <time.h>
#include "SM4.h"
		
void main()
{
	int i,j;
	u32 key[4]={0x01234567,0x89abcdef,0xfedcba98,0x76543210};
	u32 pt[4]={0x01234567,0x89abcdef,0xfedcba98,0x76543210};
	u8 pt1[64],ct1[64],ppt[64],key1[16],iv[16],iv1[16],mac[16],L[16],R[16],checksum[16];
	FILE *fp;

	if((fp=fopen("工作模式测试数据.txt","w+"))==NULL)
	{
		printf("open error!\n");
		exit(0);
	}

	for(i=0;i<16;i++)
		key1[i]=0xab*i+0x56;
	for(i=0;i<16*4;i++)
		pt1[i]=0xc5*i+0x6d;
	for(i=0;i<16;i++)
		iv[i]=0x5d*i+0xa8;

	// Print out results
	fprintf(fp,"\n	密钥：");
	for(j=0;j<16;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",key1[j]);
	}
	fprintf(fp,"\n	初始值：");
	for(j=0;j<16;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",iv[j]);
	}
	fprintf(fp,"\n	明文：");
	for(j=0;j<16*4;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",pt1[j]);
	}
	fprintf(fp,"\n-------------------------------------------\n");

	SM4_EncECB(key1,16,pt1,64,ct1);

	SM4_DecECB(key1,16,ct1,64,ppt);
	
	for(j=0;j<16*4;j++)
		if((ppt[j])!=(pt1[j]))
			printf("\nError!!!");

	fprintf(fp,"\nECB密文：");
			
	for(j=0;j<16*4;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",ct1[j]);
	}

	SM4_EncCBC(key1, 16, pt1, 64,ct1, iv,0);
	SM4_DecCBC(key1, 16, ct1, 64, ppt,iv,0);
	
	for(j=0;j<16*4;j++)
		if((ppt[j])!=(pt1[j]))
			printf("\nError!!!");
			
	fprintf(fp,"\n一次CBC密文：");
	for(j=0;j<16*4;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",ct1[j]);
	}
    for(i=0;i<16;i++)
		iv1[i]=iv[i];
	SM4_EncCBC(key1, 16, pt1, 32,ct1, iv1,1);
	SM4_EncCBC(key1, 16, pt1+32, 32,ct1+32, iv1,1);
	for(i=0;i<16;i++)
		iv1[i]=iv[i];
	SM4_DecCBC(key1, 16, ct1, 32, ppt,iv1,1);
	SM4_DecCBC(key1, 16, ct1+32, 32, ppt+32,iv1,1);
	
	for(j=0;j<16*4;j++)
		if((ppt[j])!=(pt1[j]))
			printf("\nCBCError!!!");
			
	fprintf(fp,"\n分段CBC密文：");
	for(j=0;j<16*4;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",ct1[j]);
	}

    SM4_LAPE1_ENC(key1, 16, iv, 16, pt1, 64, ct1,mac,16);

/* LAPE1 decryption */
    SM4_LAPE1_DEC(key1, 16, iv, 16, ct1, 64, ppt, mac, 16);

    for(j=0;j<16*4;j++)
		if((ppt[j])!=(pt1[j]))
			printf("\nError!!!");
			
	fprintf(fp,"\nLAPE1密文：");
	for(j=0;j<16*4;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",ct1[j]);
	}

/*  LAPE2 Mode 分段输入模式 */
/*  LAPE2 初始化 */
    SM4_LAPE2_INIT(key1, 16, iv, 16, L, R, checksum);

/*  LAPE2 加密数据 */
    SM4_LAPE2_ENC_UPDATE(key1, 16, L,R, checksum, pt1,32, ct1);
    SM4_LAPE2_ENC_UPDATE(key1, 16, L,R, checksum, pt1+32,32, ct1+32);
    SM4_LAPE2_ENC_FINAL(key1, 16, L,R, checksum, mac, 16);



/* LAPE2 解密数据获得明文 */
	SM4_LAPE2_INIT(key1, 16, iv, 16, L, R, checksum);
    SM4_LAPE2_DEC_UPDATE(key1, 16,L, R, checksum,ct1, 32, ppt);
	SM4_LAPE2_DEC_UPDATE(key1, 16,L, R, checksum,ct1+32, 32, ppt+32);

/* LAPE2 校验mac值 */
    SM4_LAPE2_DEC_FINAL(key1, 16, L, R, checksum, mac, 16);
    
	for(j=0;j<16*4;j++)
		if((ppt[j])!=(pt1[j]))
			printf("\nError!!!");
			
	fprintf(fp,"\nLAPE2密文：");
	for(j=0;j<16*4;j++)
	{
		if(j%8==0)
			fprintf(fp,"\n");
		fprintf(fp,"0x%02x,",ct1[j]);
	}

	fprintf(fp,"\n");
	fprintf(fp,"\n-------------------------------------------\n");

	fclose(fp);
}




