/* *******************************************************
文件名称：SM4.c
作    者：贾文义(jiawenyi)，56925286
版    本：SM4_V1.0
时    间：2012.5.12
描    述：分组密码算法SM4。分组长度128比特，密钥长度128比特
关联文件：SM4.h，SM4_TEST.c
历史记录：
1.作者：xx
时间：xx
修改：xx
版本：xx
 ******************************************************** */

typedef unsigned char   u8;			/* an 8 bit unsigned character type */
typedef unsigned int  u32;		/* a 32 bit unsigned integer type   */

#define RN 32
#define rotl(x,n)   (((x) << (n)) | ((x) >> (32 - (n))))

#define u8_u32(x,y)	\
	y[0]=((u32)x[0]<<24)|((u32)x[1]<<16)|((u32)x[2]<<8)|(u32)x[3];	\
	y[1]=((u32)x[4]<<24)|((u32)x[5]<<16)|((u32)x[6]<<8)|(u32)x[7];	\
	y[2]=((u32)x[8]<<24)|((u32)x[9]<<16)|((u32)x[10]<<8)|(u32)x[11];	\
	y[3]=((u32)x[12]<<24)|((u32)x[13]<<16)|((u32)x[14]<<8)|(u32)x[15]

#define u32_u8(x,y)	\
	y[0]=(u8)(x[0]>>24); y[1]=(u8)(x[0]>>16); y[2]=(u8)(x[0]>>8); y[3]=(u8)x[0];	\
	y[4]=(u8)(x[1]>>24); y[5]=(u8)(x[1]>>16); y[6]=(u8)(x[1]>>8); y[7]=(u8)x[1];	\
	y[8]=(u8)(x[2]>>24); y[9]=(u8)(x[2]>>16); y[10]=(u8)(x[2]>>8); y[11]=(u8)x[2];	\
	y[12]=(u8)(x[3]>>24); y[13]=(u8)(x[3]>>16); y[14]=(u8)(x[3]>>8); y[15]=(u8)x[3]

static const u8 S[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
	0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
	0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
	0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
	0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
	0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
	0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
	0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
	0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
	0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
	0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
	0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
	0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
	0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
	0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
	0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static const u32 CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

static const u32 FK[4]={0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC};

void SM4_key_schedule(u32 *key,u32 *ESK,u32 *DSK)
{
    int i;
	u32 K[4],t,y;

	K[0] = FK[0] ^ key[0];
	K[1] = FK[1] ^ key[1];
	K[2] = FK[2] ^ key[2];
	K[3] = FK[3] ^ key[3];
	
	for(i=0; i<RN; i++)
	{
		t = K[1] ^ K[2] ^ K[3] ^ CK[i];
		
		y = ((u32)S[t>>24]<<24) | ((u32)S[(t>>16)&0xff]<<16) |
			((u32)S[(t>>8)&0xff]<<8) | ((u32)S[t&0xff]);

		t = y^ rotl(y,13) ^ rotl(y,23);

		K[0] ^= t;

		ESK[i] = K[0];
		DSK[RN-i-1] = ESK[i];

		t = K[0];
		K[0] = K[1];
		K[1] = K[2];
		K[2] = K[3];
		K[3] = t;
	}
}

void SM4_crypt(u32 in_blk[4], u32 out_blk[4], u32 *skey)
{
	int i;
	u32 x[4],y,t;

	x[0]=in_blk[0];
	x[1]=in_blk[1];	
	x[2]=in_blk[2];	
	x[3]=in_blk[3];
	
	for(i=0; i<RN; i++)
	{
		t=x[1]^x[2]^x[3]^skey[i];
		
		y=((u32)S[t>>24]<<24)|((u32)S[(t>>16)&0xff]<<16)|
			((u32)S[(t>>8)&0xff]<<8)|((u32)S[t&0xff]);

		t=y^rotl(y,24);
		y=y^rotl(t,16);
		t=t^rotl(y,2);

		x[0]^=t;
		t=x[0];
		x[0]=x[1];
		x[1]=x[2];
		x[2]=x[3];
		x[3]=t;
	}

	out_blk[0]=x[3];
	out_blk[1]=x[2];
	out_blk[2]=x[1];
	out_blk[3]=x[0];
}


// ECB 模式，加密 
int SM4_EncECB(unsigned char *key,unsigned int key_len, unsigned char *pt, unsigned int pt_len,unsigned char *ct)
{
	int i;
	u32 x[4],k[4];
	u32 esk[32],dsk[32];
    
	if ((pt_len & 0xf) != 0)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}

	u8_u32(key,k);
    SM4_key_schedule(k,esk,dsk);
	
	for(i = 0; i<(int)pt_len; i+= 16)
	{
		u8_u32((pt+i),x);
		SM4_crypt(x,x,esk);
		u32_u8(x,(ct+i));
	}

	return 0;
}

// ECB 模式，解密 
int SM4_DecECB(unsigned char *key,unsigned int key_len, unsigned char *ct, unsigned int ct_len,unsigned char *pt )
{
	int i;
	u32 x[4],k[4];
	u32 esk[32],dsk[32];
    
	if ( (ct_len & 0xf) != 0 )
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}

	u8_u32(key,k);
	SM4_key_schedule(k,esk,dsk);
	
	for(i=0; i<(int)ct_len; i+=16)
	{
		u8_u32((ct+i),x);
		SM4_crypt(x,x,dsk);
		u32_u8(x,(pt+i));
	}

	return 0;
}

// CBC 模式，加密 
int SM4_EncCBC(unsigned char *key, unsigned int key_len,unsigned char *pt,
				 unsigned int pt_len,unsigned char *ct,unsigned char *iv,unsigned int flag)
{
	int i;
	u32 x[32],y[32],k[4];
	u32 esk[32],dsk[32];

    if ((pt_len & 0xf) != 0)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}
   
	u8_u32(key,k);
	SM4_key_schedule(k,esk,dsk);
	
	u8_u32(iv,y);
	for (i=0; i<(int)pt_len; i+=16)
	{
		u8_u32((pt+i),x);
		y[0]^=x[0];
		y[1]^=x[1];	
		y[2]^=x[2];	
		y[3]^=x[3];
		SM4_crypt(y,y,esk);
		u32_u8(y,(ct+i));
	}

	if (flag == 1)
	{
		u32_u8(y,iv);
	}

	return 0;
		
}

// CBC 模式，解密 
int SM4_DecCBC(unsigned char *key, unsigned int key_len,unsigned char *ct,
				 unsigned int ct_len,unsigned char *pt,unsigned char *iv,unsigned int flag)
{
	int i;
	u32 x[4],y[4],z[4],k[4];
    u32 esk[32],dsk[32];
    
	if ((ct_len & 0xf) != 0)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}

	u8_u32(key,k);
	SM4_key_schedule(k,esk,dsk);
	
	u8_u32(iv,y);
	for (i=0; i<(int)ct_len; i+=16 )
	{
		u8_u32((ct+i),z);
		SM4_crypt(z,x,dsk);
		x[0]^=y[0];
		x[1]^=y[1];
		x[2]^=y[2];
		x[3]^=y[3];
		u32_u8(x,(pt+i));
		y[0]=z[0];
		y[1]=z[1];
		y[2]=z[2];
		y[3]=z[3];
	}

	if (flag == 1)
	{
		u32_u8(y,iv);
	}

	return 0;
}

/* LAPE1 Mode which input data with one time */
/* LAPE1 encryption */
int SM4_LAPE1_ENC(unsigned char *key, unsigned int key_len, unsigned char *nonce, 
					 unsigned int nonce_len, unsigned char *pt,  unsigned int pt_len,
					 unsigned char *ct, unsigned char *mac,  unsigned int mac_len)
{
	unsigned int i, j;
	unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];
	unsigned char L[16], R[16], Z[16];
	unsigned char in[16], out[16], temp, checksum[16];

	/* verifying length */
	if ((pt_len & 0xf) != 0)
	{
		return -1;
	}

	if (nonce_len != 16)
	{
		return -1;
	}

	if (mac_len > 16)
	{
		return -1;
	}
	
	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);

	/* initializing x */
	for (i=0; i<4; i++)  
	{
		x[i] = 0;
	}

	/* initializing checksum */
	for (i=0; i<16; i++) 
	{
		checksum[i] = 0;
	}

    /* obtaining L */
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, L);

	/* obtaining R */
	for (i=0; i<16; i++)
	{
		in[i] = nonce[i] ^ L[i];
	}

	u8_u32(in, x);
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, R);

    /* dealing with(i.e,encrypting) 1,2,...,m round */
	for (i=0; i<pt_len; i+=16)
	{
		temp = L[0];

		for (j=0; j<15; j++)
		{
			L[j] = (L[j]<<1) ^ (L[j+1]>>7);  // if left(L)=0, then L=L<<1
		}

		L[15] = L[15]<<1;

		if ((temp & 0x80) != 0)              // if left(L)=1, then L=(L<<1)^10000111
		{
			L[15] = L[15] ^ 0x87;
		}
		
		for (j=0; j<16; j++)
		{
			Z[j] = L[j] ^ R[j];
			in[j] = pt[i+j] ^ Z[j];
			checksum[j] = checksum[j] ^ pt[i+j];
		}

		u8_u32(in, x);
    	SM4_crypt(x, x, en_subkey);
	    u32_u8(x, out);

		for (j=0; j<16; j++)
		{
			ct[i+j] = out[j] ^ Z[j];
		}
	}// end for (i=0; i<pt_len; i+=16)

    /* dealing with(i.e,encrypting) the (m+1)th round, the last round */

	for (j=0; j<15; j++)
	{
		Z[j] = (L[j]<<1) ^ (L[j+1]>>7);
	}
	
	Z[15] = L[15]<<1;

	if ((L[0] & 0x80) != 0)
	{
		Z[15] = Z[15] ^ 0x87;
	}

	for (j=0; j<16; j++)
	{
		Z[j] = Z[j] ^ R[j];
		in[j] = checksum[j] ^ Z[j];
	}

	u8_u32(in, x);
    SM4_crypt(x, x, en_subkey);
	u32_u8(x, out);

	/* truncating needed bytes of mac(from left to right) */
	for (i=0; i<mac_len; i++)  
	{
		mac[i] = out[i];
	}

	return 0;
}

/* LAPE1 decryption */
int SM4_LAPE1_DEC(unsigned char *key, unsigned int key_len, unsigned char *nonce,
				   unsigned int nonce_len, unsigned char *ct, unsigned int ct_len, 
				   unsigned char *pt, unsigned char *mac, unsigned int mac_len)
{
	unsigned int i, j, k=0;
    unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];
	unsigned char L[16], R[16], Z[16];
	unsigned char in[16], out[16], temp, checksum[16];

	/* verifying length */
	if ((ct_len & 0xf) != 0)
	{
		return -1;
	}

	if (nonce_len != 16)
	{
		return -1;
	}

	if (mac_len > 16)
	{
		return -1;
	}
	
	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);

	/* initializing x */
	for (i=0; i<4; i++)  
	{
		x[i] = 0;
	}

	/* initializing checksum */
	for (i=0; i<16; i++)  
	{
		checksum[i] = 0;
	}

    /* obtaining L */
	
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, L);

	/* obtaining R */
	for (i=0; i<16; i++)
	{
		in[i] = nonce[i] ^ L[i];
	}

	u8_u32(in, x);
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, R); 

    /* dealing with(i.e,decrypting) 1,2,...,m round */
	for (i=0; i<ct_len; i+=16)
	{
		temp = L[0];

		for (j=0; j<15; j++)
		{
			L[j] = (L[j]<<1) ^ (L[j+1]>>7);
		}
		
		L[15] = L[15]<<1;

		if ((temp & 0x80) != 0)
		{
			L[15] = L[15] ^ 0x87;
		}

		for (j=0; j<16; j++)
		{
			Z[j] = L[j] ^ R[j];
			in[j] = ct[i+j] ^ Z[j];
		}

		u8_u32(in, x);
        SM4_crypt(x, x, de_subkey);
	    u32_u8(x, out);

		for (j=0; j<16; j++)
		{
			pt[i+j] = out[j] ^ Z[j];
			checksum[j] = checksum[j] ^ pt[i+j];
		}
	}// end for (i=0; i<ct_len; i+=16)

    /* dealing with(i.e,encrypting) the (m+1)th round, the last round */
	
	for (j=0; j<15; j++)
	{
		Z[j] = (L[j]<<1) ^ (L[j+1]>>7); 
	}
	
	Z[15] = L[15]<<1;

	if ((L[0] & 0x80) != 0) 
	{
		Z[15] = Z[15] ^ 0x87;
	}

	for (j=0; j<16; j++)
	{
		Z[j] = Z[j] ^ R[j];
		in[j] = checksum[j] ^ Z[j];
	}

	u8_u32(in, x);
    SM4_crypt(x, x, en_subkey);
	u32_u8(x, L);

	/* verifying mac */
	for (j=0; j<mac_len; j++)
	{
		if (mac[j]==L[j])
		{
			k++;
		}
	}

	if (k==mac_len)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

/*  LAPE2 Mode which input data with sereval times */
/*  LAPE2 initialization */
int SM4_LAPE2_INIT(unsigned char *key, unsigned int key_len, unsigned char *nonce,
						unsigned int nonce_len, unsigned char *L,
						unsigned char *R, unsigned char *checksum)
{
	unsigned int i;
	unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];

	/* verifying length */
	if (key_len != 16)
	{
		return -1;
	}

	if (nonce_len != 16)
	{
		return -1;
	}
	
	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);

	/* initializing IV */
	for (i=0; i<4; i++)  
	{
		x[i] = 0;
	}

    /* obtaining L */
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, L);

	/* obtaining R */
	for (i=0; i<16; i++)
	{
		R[i] = nonce[i] ^ L[i];
	}

	u8_u32(R, x);
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, R);
	
	/* initializing checksum */
	for (i=0; i<16; i++)  
	{
		checksum[i] = 0;
	}

	return 0;
}

/*  LAPE2 encryption(obtain the ciphertext) */
int SM4_LAPE2_ENC_UPDATE(unsigned char *key, unsigned int key_len, unsigned char *L,
						  unsigned char *R, unsigned char *checksum, unsigned char *pt,
						  unsigned int pt_len, unsigned char *ct)
{
	unsigned int i, j;
	unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];
	unsigned char Z[16], in[16], out[16], temp;

	/* verifying length */
	if (pt_len % 16)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}
	
	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);

    /* dealing with(i.e,encrypting) 1,2,...,m round */
	for (i=0; i<pt_len; i+=16)
	{
		temp = L[0];

		for (j=0; j<15; j++)
		{
			L[j] = (L[j]<<1) ^ (L[j+1]>>7);  
		}

		L[15] = L[15]<<1;

		if ((temp & 0x80) != 0) 
		{
			L[15] = L[15] ^ 0x87;
		}
		
		for (j=0; j<16; j++)
		{
			Z[j] = L[j] ^ R[j];
			in[j] = pt[i+j] ^ Z[j];
			checksum[j] = checksum[j] ^ pt[i+j];
		}

		u8_u32(in, x);
	    SM4_crypt(x, x, en_subkey);
	    u32_u8(x, out);

		for (j=0; j<16; j++)
		{
			ct[i+j] = out[j] ^ Z[j];
		}
	}// end for (i=0; i<pt_len; i+=16)

	return 0;
}

/*LAPE2 encryption(obtain  mac) */
int SM4_LAPE2_ENC_FINAL(unsigned char *key, unsigned int key_len, unsigned char *L,
						 unsigned char *R, unsigned char *checksum, 
						 unsigned char *mac, unsigned int mac_len)
{
	unsigned int i;
	unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];
	unsigned char Z[16], in[16], out[16];
	
	/* verifying length */
	if (key_len != 16)
	{
		return -1;
	}

	if (mac_len > 16)
	{
		return -1;
	}
	
	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);
	
	/* dealing with(i.e,encrypting) the (m+1)th round, the last round */

	for (i=0; i<15; i++)
	{
		Z[i] = (L[i]<<1) ^ (L[i+1]>>7);
	}
	
	Z[15] = L[15]<<1;

	if ((L[0] & 0x80) != 0) 
	{
		Z[15] = Z[15] ^ 0x87;
	}

	for (i=0; i<16; i++)
	{
		Z[i] = Z[i] ^ R[i];
		in[i] = checksum[i] ^ Z[i];
	}

	u8_u32(in, x);
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, out);

	/* truncating needed bytes of mac(from left to right) */
	for (i=0; i<mac_len; i++)
	{
		mac[i] = out[i];
	}

	return 0;
}

/* LAPE2 decryption(obtain the plaintext) */
int SM4_LAPE2_DEC_UPDATE(unsigned char *key, unsigned int key_len, unsigned char *L, 
						  unsigned char *R, unsigned char *checksum, unsigned char *ct, 
						  unsigned int ct_len, unsigned char *pt)
{
	unsigned int i, j;
	unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];
	unsigned char Z[16], in[16], out[16], temp;

	/* verifying length */
	if (ct_len % 16)
	{
		return -1;
	}

	if (key_len != 16)
	{
		return -1;
	}
	
	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);

    /* dealing with(i.e,decrypting) 1,2,...,m round */
	for (i=0; i<ct_len; i+=16)
	{
		temp = L[0];

		for (j=0; j<15; j++)
		{
			L[j] = (L[j]<<1) ^ (L[j+1]>>7);
		}
		
		L[15] = L[15]<<1;

		if ((temp & 0x80) != 0) 
		{
			L[15] = L[15] ^ 0x87;
		}

		for (j=0; j<16; j++)
		{
			Z[j] = L[j] ^ R[j];
			in[j] = ct[i+j] ^ Z[j];
		}

		u8_u32(in, x);
 	    SM4_crypt(x, x, de_subkey);
	    u32_u8(x, out);

		for (j=0; j<16; j++)
		{
			pt[i+j] = out[j] ^ Z[j];
			checksum[j] = checksum[j] ^ pt[i+j];
		}
	}// end for (i=0; i<ct_len; i+=16)

	return 0;
}

/* LAPE2 decryption(verifying mac) */
int SM4_LAPE2_DEC_FINAL(unsigned char *key, unsigned int key_len, unsigned char *L, 
						 unsigned char *R, unsigned char *checksum, 
						 unsigned char *mac, unsigned int mac_len)
{
	unsigned int i, k=0;
	unsigned int x[4];
	unsigned int tkey[4];
	unsigned int en_subkey[32];
    unsigned int de_subkey[32];
	unsigned char Z[16], in[16], out[16];

	/* verifying length */
	if (key_len != 16)
	{
		return -1;
	}
	
	if (mac_len > 16)
	{
		return -1;
	}

	u8_u32(key, tkey);
	SM4_key_schedule(tkey, en_subkey, de_subkey);
	
	/* dealing with(i.e,encrypting) the (m+1)th round, the last round */
	
	for (i=0; i<15; i++)
	{
		Z[i] = (L[i]<<1) ^ (L[i+1]>>7);
	}
	
	Z[15] = L[15]<<1;

	if ((L[0] & 0x80) != 0)
	{
		Z[15] = Z[15] ^ 0x87;
	}

	for (i=0; i<16; i++)
	{
		Z[i] = Z[i] ^ R[i];
		in[i] = checksum[i] ^ Z[i];
	}

	u8_u32(in, x);
	SM4_crypt(x, x, en_subkey);
	u32_u8(x, out);

	/* verifying mac */
	for (i=0; i<mac_len; i++) 
	{
		if (mac[i]==out[i])
		{
			k++;
		}
	}

	if (k==mac_len)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

