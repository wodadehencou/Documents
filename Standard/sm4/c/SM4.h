/*	���������㷨SM4�����鳤��128���أ���Կ����128���ء� */
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

// ECB ģʽ������ 
int SM4_EncECB(unsigned char *key,unsigned int key_len, unsigned char *pt, unsigned int pt_len,unsigned char *ct);
//����������
//    ���룺key��			��Կ�׵�ַ
//          key_len��		��Կ����,16�ֽ�
//          pt��			���������������׵�ַ
//          pt_len��		�������������ݳ��ȣ�Ϊ16�ı���
//    �����ct��			���ܺ�������׵�ַ��������������ĳ�����ͬ��
//����ֵ��
//0��			����ɹ�
//-1��			����Ƿ�

// ECB ģʽ������ 
int SM4_DecECB(unsigned char *key,unsigned int key_len, unsigned char *ct, unsigned int ct_len,unsigned char *pt);
//����������
//    ���룺key��			��Կ�׵�ַ
//          key_len��		��Կ����,16�ֽ�
//          ct��			���������������׵�ַ
//          ct_len��		�������������ݳ��ȣ�Ϊ16�ı���
//    �����pt��			���ܺ�������׵�ַ��������������ĳ�����ͬ��
//����ֵ��
//0��			����ɹ�
//-1��			����Ƿ�

// CBC ģʽ������ 
int SM4_EncCBC(unsigned char *key, unsigned int key_len,unsigned char *pt,
				 unsigned int pt_len,unsigned char *ct,unsigned char *iv,unsigned int flag);
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����,16�ֽ�
//        pt��			���������������׵�ַ
//        pt_len��		�������������ݳ���,Ϊ16�ı���
//        iv��			��ʼ�����׵�ַ����������鳤����ͬ��
//        flag=0��		һ�ε���
//        flag=1��		�ֶε���
//�����  ct��			���ܺ�������׵�ַ��������������ĳ�����ͬ��
//����ֵ��
//0��			����ɹ�
//-1��			����Ƿ�

// CBC ģʽ������ 
int SM4_DecCBC(unsigned char *key, unsigned int key_len,unsigned char *ct,
				 unsigned int ct_len,unsigned char *pt,unsigned char *iv,unsigned int flag);
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����,16�ֽ�
//        ct��			���������������׵�ַ
//        ct_len��		�������������ݳ���,Ϊ16�ı���
//        iv��			��ʼ�����׵�ַ����������鳤����ͬ��
//        flag=0��		һ�ε���
//        flag=1��		�ֶε���
//�����  ct��			���ܺ�������׵�ַ��������������ĳ�����ͬ��
//����ֵ��
//0��			����ɹ�
//-1��			����Ƿ�

/* LAPE1 Mode һ������ģʽ */
/* LAPE1 encryption */
int SM4_LAPE1_ENC(unsigned char *key, unsigned int key_len, unsigned char *nonce, 
					 unsigned int nonce_len, unsigned char *pt,  unsigned int pt_len,
					 unsigned char *ct, unsigned char *mac,  unsigned int mac_len);
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����,16�ֽ�
//        nonce��		��ʼ�����׵�ַ
//        nonce_len��	��ʼ�������ȣ�����鳤����ͬ��16�ֽڣ�
//        pt��			���������������׵�ַ
//        pt_len��		�������������ݳ��ȣ����鳤�ȣ�16�ֽڣ�����������
//        mac_len��		��֤�����ݳ��ȣ�С�ڻ���ڷ��鳤�ȣ�
//�����ct��			���ܺ�������׵�ַ
//        mac��			��֤������
//����ֵ��
//		  0��			����ɹ�
//		  -1��			����Ƿ�

/* LAPE1 decryption */
int SM4_LAPE1_DEC(unsigned char *key, unsigned int key_len, unsigned char *nonce,
				   unsigned int nonce_len, unsigned char *ct, unsigned int ct_len, 
				   unsigned char *pt, unsigned char *mac, unsigned int mac_len);
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����,16�ֽ�
//        nonce��		��ʼ�����׵�ַ
//        nonce_len��	��ʼ�������ȣ�����鳤����ͬ��
//        ct��			���������������׵�ַ
//        ct_len��		�������������ݳ��ȷ��鳤�ȣ�16�ֽڣ�����������
//        mac��			��֤�������׵�ַ
//        mac_len��		��֤�����ݳ��ȣ�С�ڻ���ڷ��鳤�ȣ�
//�����pt��			���ܺ�������׵�ַ
//  ����ֵ��
//		  0��			����ɹ�
//		  1��			��֤����
//		  -1��			����Ƿ�


/*  LAPE2 Mode �ֶ�����ģʽ */
/*  LAPE2 ��ʼ�� */
int SM4_LAPE2_INIT(unsigned char *key, unsigned int key_len, unsigned char *nonce,
						unsigned int nonce_len, unsigned char *L,
						unsigned char *R, unsigned char *checksum);
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����
//        nonce��		��ʼ�����׵�ַ
//        nonce_len��	��ʼ�������ȣ�����鳤����ͬ��
//�����  L��			ȫ0���ܺ�������׵�ַ��ȫ0��L�ĳ��Ⱦ�����鳤����ͬ��
//        R��			nonce��L������ܵ������׵�ַ����������鳤����ͬ��
//        checksum��	ȫ0�������׵�ַ����������鳤����ͬ��
//  ����ֵ��
//		  0��			����ɹ�
//		  -1��			����Ƿ�


/*  LAPE2 �������� */
int SM4_LAPE2_ENC_UPDATE(unsigned char *key, unsigned int key_len, unsigned char *L,
						  unsigned char *R, unsigned char *checksum, unsigned char *pt,
						  unsigned int pt_len, unsigned char *ct);
//�����������ֶ��������ĵļ��ܶ�ģ�飬����L��checksum���������
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����
//        L��			��λ���ʵʱ�����׵�ַ����������鳤����ͬ��
//        R��			���ó�ʼ������������������׵�ַ����������鳤����ͬ��
//        checksum��		�����Ŀ�����������׵�ַ����������鳤����ͬ��
//        pt��			���������������׵�ַ
//        pt_len��		�������������ݳ��ȣ����鳤�ȵ���������
//�����  ct��			���ܺ�������׵�ַ
//        L��			��λ���ʵʱ�����׵�ַ����������鳤����ͬ��
//        checksum��		�����Ŀ�����������׵�ַ����������鳤����ͬ��
//  ����ֵ��
//		  0��			����ɹ�
//		  -1��			����Ƿ�

/* LAPE2 ���mac */
int SM4_LAPE2_ENC_FINAL(unsigned char *key, unsigned int key_len, unsigned char *L,
						 unsigned char *R, unsigned char *checksum, 
						 unsigned char *mac, unsigned int mac_len);
//����������������Ϣ��֤��
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����
//        L��			��λ���ʵʱ�����׵�ַ����������鳤����ͬ��
//        R��			���ó�ʼ������������������׵�ַ����������鳤����ͬ��
//        checksum��	�����Ŀ�����������׵�ַ����������鳤����ͬ��
//        mac_len��		��֤�����ݳ��ȣ�һ��С�ڻ���ڷ��鳤�ȣ�
//�����  mac��			��֤�������׵�ַ
//����ֵ��
//		  0��			����ɹ�
//		  -1��			����Ƿ�


/* LAPE2 �������ݻ������ */
int SM4_LAPE2_DEC_UPDATE(unsigned char *key, unsigned int key_len, unsigned char *L, 
						  unsigned char *R, unsigned char *checksum, unsigned char *ct, 
						  unsigned int ct_len, unsigned char *pt);
//�����������ֶ��������ĵĽ��ܶ�ģ�飬����L��checksum���������
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����
//        L��			��λ���ʵʱ�����׵�ַ����������鳤����ͬ��
//        R��			���ó�ʼ������������������׵�ַ����������鳤����ͬ��
//        checksum��		�����Ŀ�����������׵�ַ����������鳤����ͬ��
//        ct��			���������������׵�ַ
//        ct_len��		�������������ݳ��ȣ����鳤�ȵ���������
//�����  pt��			���ܺ�������׵�ַ
//        L��			��λ���ʵʱ�����׵�ַ����������鳤����ͬ��
//        checksum��		�����Ŀ�����������׵�ַ����������鳤����ͬ��
//  ����ֵ��
//		  0��			����ɹ�
//		  -1��			����Ƿ�


/* LAPE2 У��macֵ */
int SM4_LAPE2_DEC_FINAL(unsigned char *key, unsigned int key_len, unsigned char *L, 
						 unsigned char *R, unsigned char *checksum, 
						 unsigned char *mac, unsigned int mac_len);
//������������֤macֵ
//����������
//���룺  key��			��Կ�׵�ַ
//        key_len��		��Կ����
//        L��			��λ���ʵʱ�����׵�ַ����������鳤����ͬ��
//        R��			���ó�ʼ������������������׵�ַ����������鳤����ͬ��
//        checksum��	�����Ŀ�����������׵�ַ����������鳤����ͬ��
//        mac��			��֤�������׵�ַ
//        mac_len��		��֤�����ݳ��ȣ�һ��С�ڻ���ڷ��鳤�ȣ�
//�����
//		  ��
//  ����ֵ��
//		  0��			����ɹ�
//		  1��			��֤ʧ��
//		  -1��			����Ƿ�

#endif