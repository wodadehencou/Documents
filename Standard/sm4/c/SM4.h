/*	分组密码算法SM4。分组长度128比特，密钥长度128比特。 */
#ifndef _SM4_H_H_
#define _SM4_H_H_

typedef unsigned char   u8;			/* an 8 bit unsigned character type */
typedef unsigned long int  u32;		/* a 32 bit unsigned integer type   */

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

// ECB 模式，加密 
int SM4_EncECB(unsigned char *key,unsigned int key_len, unsigned char *pt, unsigned int pt_len,unsigned char *ct);
//参数描述：
//    输入：key，			密钥首地址
//          key_len，		密钥长度,16字节
//          pt，			待加密明文数据首地址
//          pt_len，		待加密明文数据长度，为16的倍数
//    输出：ct，			加密后的密文首地址（输出长度与明文长度相同）
//返回值：
//0，			运算成功
//-1，			输入非法

// ECB 模式，解密 
int SM4_DecECB(unsigned char *key,unsigned int key_len, unsigned char *ct, unsigned int ct_len,unsigned char *pt);
//参数描述：
//    输入：key，			密钥首地址
//          key_len，		密钥长度,16字节
//          ct，			待解密密文数据首地址
//          ct_len，		待解密密文数据长度，为16的倍数
//    输出：pt，			解密后的明文首地址（输出长度与密文长度相同）
//返回值：
//0，			运算成功
//-1，			输入非法

// CBC 模式，加密 
int SM4_EncCBC(unsigned char *key, unsigned int key_len,unsigned char *pt,
				 unsigned int pt_len,unsigned char *ct,unsigned char *iv,unsigned int flag);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度,16字节
//        pt，			待加密明文数据首地址
//        pt_len，		待加密明文数据长度,为16的倍数
//        iv，			初始向量首地址（长度与分组长度相同）
//        flag=0，		一次调用
//        flag=1，		分段调用
//输出：  ct，			加密后的密文首地址（输出长度与明文长度相同）
//返回值：
//0，			运算成功
//-1，			输入非法

// CBC 模式，解密 
int SM4_DecCBC(unsigned char *key, unsigned int key_len,unsigned char *ct,
				 unsigned int ct_len,unsigned char *pt,unsigned char *iv,unsigned int flag);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度,16字节
//        ct，			待解密密文数据首地址
//        ct_len，		待解密密文数据长度,为16的倍数
//        iv，			初始向量首地址（长度与分组长度相同）
//        flag=0，		一次调用
//        flag=1，		分段调用
//输出：  ct，			加密后的密文首地址（输出长度与明文长度相同）
//返回值：
//0，			运算成功
//-1，			输入非法

/* LAPE1 Mode 一次输入模式 */
/* LAPE1 encryption */
int SM4_LAPE1_ENC(unsigned char *key, unsigned int key_len, unsigned char *nonce, 
					 unsigned int nonce_len, unsigned char *pt,  unsigned int pt_len,
					 unsigned char *ct, unsigned char *mac,  unsigned int mac_len);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度,16字节
//        nonce，		初始向量首地址
//        nonce_len，	初始向量长度（与分组长度相同，16字节）
//        pt，			待加密明文数据首地址
//        pt_len，		待加密明文数据长度（分组长度（16字节）的整数倍）
//        mac_len，		验证码数据长度（小于或等于分组长度）
//输出：ct，			加密后的密文首地址
//        mac，			验证码数据
//返回值：
//		  0，			运算成功
//		  -1，			输入非法

/* LAPE1 decryption */
int SM4_LAPE1_DEC(unsigned char *key, unsigned int key_len, unsigned char *nonce,
				   unsigned int nonce_len, unsigned char *ct, unsigned int ct_len, 
				   unsigned char *pt, unsigned char *mac, unsigned int mac_len);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度,16字节
//        nonce，		初始向量首地址
//        nonce_len，	初始向量长度（与分组长度相同）
//        ct，			待解密密文数据首地址
//        ct_len，		待解密密文数据长度分组长度（16字节）的整数倍）
//        mac，			验证码数据首地址
//        mac_len，		验证码数据长度（小于或等于分组长度）
//输出：pt，			解密后的明文首地址
//  返回值：
//		  0，			运算成功
//		  1，			验证错误
//		  -1，			输入非法


/*  LAPE2 Mode 分段输入模式 */
/*  LAPE2 初始化 */
int SM4_LAPE2_INIT(unsigned char *key, unsigned int key_len, unsigned char *nonce,
						unsigned int nonce_len, unsigned char *L,
						unsigned char *R, unsigned char *checksum);
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度
//        nonce，		初始向量首地址
//        nonce_len，	初始向量长度（与分组长度相同）
//输出：  L，			全0加密后的密文首地址（全0和L的长度均与分组长度相同）
//        R，			nonce和L异或后加密的密文首地址（长度与分组长度相同）
//        checksum，	全0的数据首地址（长度与分组长度相同）
//  返回值：
//		  0，			运算成功
//		  -1，			输入非法


/*  LAPE2 加密数据 */
int SM4_LAPE2_ENC_UPDATE(unsigned char *key, unsigned int key_len, unsigned char *L,
						  unsigned char *R, unsigned char *checksum, unsigned char *pt,
						  unsigned int pt_len, unsigned char *ct);
//功能描述：分段输入明文的加密段模块，更新L和checksum并输出密文
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度
//        L，			移位后的实时数据首地址（长度与分组长度相同）
//        R，			调用初始化函数后的密文数据首地址（长度与分组长度相同）
//        checksum，		与明文块异或后的数据首地址（长度与分组长度相同）
//        pt，			待加密明文数据首地址
//        pt_len，		待加密明文数据长度（分组长度的整数倍）
//输出：  ct，			加密后的密文首地址
//        L，			移位后的实时数据首地址（长度与分组长度相同）
//        checksum，		与明文块异或后的数据首地址（长度与分组长度相同）
//  返回值：
//		  0，			运算成功
//		  -1，			输入非法

/* LAPE2 获得mac */
int SM4_LAPE2_ENC_FINAL(unsigned char *key, unsigned int key_len, unsigned char *L,
						 unsigned char *R, unsigned char *checksum, 
						 unsigned char *mac, unsigned int mac_len);
//功能描述：计算消息验证码
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度
//        L，			移位后的实时数据首地址（长度与分组长度相同）
//        R，			调用初始化函数后的密文数据首地址（长度与分组长度相同）
//        checksum，	与明文块异或后的数据首地址（长度与分组长度相同）
//        mac_len，		验证码数据长度（一般小于或等于分组长度）
//输出：  mac，			验证码数据首地址
//返回值：
//		  0，			运算成功
//		  -1，			输入非法


/* LAPE2 解密数据获得明文 */
int SM4_LAPE2_DEC_UPDATE(unsigned char *key, unsigned int key_len, unsigned char *L, 
						  unsigned char *R, unsigned char *checksum, unsigned char *ct, 
						  unsigned int ct_len, unsigned char *pt);
//功能描述：分段输入密文的解密段模块，更新L和checksum并输出明文
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度
//        L，			移位后的实时数据首地址（长度与分组长度相同）
//        R，			调用初始化函数后的密文数据首地址（长度与分组长度相同）
//        checksum，		与明文块异或后的数据首地址（长度与分组长度相同）
//        ct，			待解密密文数据首地址
//        ct_len，		待解密密文数据长度（分组长度的整数倍）
//输出：  pt，			解密后的明文首地址
//        L，			移位后的实时数据首地址（长度与分组长度相同）
//        checksum，		与明文块异或后的数据首地址（长度与分组长度相同）
//  返回值：
//		  0，			运算成功
//		  -1，			输入非法


/* LAPE2 校验mac值 */
int SM4_LAPE2_DEC_FINAL(unsigned char *key, unsigned int key_len, unsigned char *L, 
						 unsigned char *R, unsigned char *checksum, 
						 unsigned char *mac, unsigned int mac_len);
//功能描述：验证mac值
//参数描述：
//输入：  key，			密钥首地址
//        key_len，		密钥长度
//        L，			移位后的实时数据首地址（长度与分组长度相同）
//        R，			调用初始化函数后的密文数据首地址（长度与分组长度相同）
//        checksum，	与明文块异或后的数据首地址（长度与分组长度相同）
//        mac，			验证码数据首地址
//        mac_len，		验证码数据长度（一般小于或等于分组长度）
//输出：
//		  无
//  返回值：
//		  0，			运算成功
//		  1，			验证失败
//		  -1，			输入非法

#endif