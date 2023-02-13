#ifndef __TINY_STEAM_CLIENT_STEAMENCRYPTEDCHANNEL_HPP__
#define __TINY_STEAM_CLIENT_STEAMENCRYPTEDCHANNEL_HPP__

#pragma warning( disable: 4251 )
#pragma warning( disable: 4275 )

#include <rsa.h>
#include <randpool.h>
#include <validate.h>
#include <modes.h>
#include <aes.h>
#include <hmac.h>
#include <gzip.h>
#include <zdeflate.h>
#include "utility/checksum_crc.h"

using namespace CryptoPP;

inline const char* pRandomSeed = "tiny-steam-client";
inline const byte pRsaSteamPublicKey[] = {
	0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
	0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0xDF, 0xEC, 0x1A,
	0xD6, 0x2C, 0x10, 0x66, 0x2C, 0x17, 0x35, 0x3A, 0x14, 0xB0, 0x7C, 0x59, 0x11, 0x7F, 0x9D, 0xD3,
	0xD8, 0x2B, 0x7A, 0xE3, 0xE0, 0x15, 0xCD, 0x19, 0x1E, 0x46, 0xE8, 0x7B, 0x87, 0x74, 0xA2, 0x18,
	0x46, 0x31, 0xA9, 0x03, 0x14, 0x79, 0x82, 0x8E, 0xE9, 0x45, 0xA2, 0x49, 0x12, 0xA9, 0x23, 0x68,
	0x73, 0x89, 0xCF, 0x69, 0xA1, 0xB1, 0x61, 0x46, 0xBD, 0xC1, 0xBE, 0xBF, 0xD6, 0x01, 0x1B, 0xD8,
	0x81, 0xD4, 0xDC, 0x90, 0xFB, 0xFE, 0x4F, 0x52, 0x73, 0x66, 0xCB, 0x95, 0x70, 0xD7, 0xC5, 0x8E,
	0xBA, 0x1C, 0x7A, 0x33, 0x75, 0xA1, 0x62, 0x34, 0x46, 0xBB, 0x60, 0xB7, 0x80, 0x68, 0xFA, 0x13,
	0xA7, 0x7A, 0x8A, 0x37, 0x4B, 0x9E, 0xC6, 0xF4, 0x5D, 0x5F, 0x3A, 0x99, 0xF9, 0x9E, 0xC4, 0x3A,
	0xE9, 0x63, 0xA2, 0xBB, 0x88, 0x19, 0x28, 0xE0, 0xE7, 0x14, 0xC0, 0x42, 0x89, 0x02, 0x01, 0x11,
};

class SteamEncryptedChannel
{
public:
	void Init()
	{
		ArraySource pubArr(pRsaSteamPublicKey, sizeof(pRsaSteamPublicKey), true);
		RSA::PublicKey pubKey;
		pubKey.Load(pubArr);
		m_RsaEncryptor = RSAES_OAEP_SHA_Encryptor(pubKey);

		m_RandomPool.IncorporateEntropy((byte*)pRandomSeed, strlen(pRandomSeed));
		GenerateRandomBytes(m_Aes256Key, 32);

		m_AesEcbEncryptor.SetKey(m_Aes256Key, 32);
		m_AesEcbDecryptor.SetKey(m_Aes256Key, 32);
	}

public:
	size_t RSAEncrypt(const char* pData, size_t dataLen, char* pDest, size_t destLen)
	{
		size_t cipherTextSize = RSACipherLength(dataLen);
		if (destLen < cipherTextSize)
			return 0;

		m_RsaEncryptor.Encrypt(m_RandomPool, (byte*)pData, dataLen, (byte*)pDest);
		return cipherTextSize;
	}

	size_t SymmetricEncryptWithHMACIV(const char* pData, size_t dataLen, char* pDest, size_t destLen)
	{
		auto totalSize = GetAesCipherLength(dataLen) + 16;
		if (destLen < totalSize)
			return 0;

		byte random[3];
		byte iv[16];
		byte sha1[20];

		//Calculate hmac iv, IV is HMAC-SHA1(Random(3) + Plaintext) + Random(3). (Same random values for both)
		HMAC<SHA1> hmac_encryptor(m_Aes256Key, 16);
		GenerateRandomBytes(random, 3);
		memcpy(iv + (sizeof(iv) - sizeof(random)), random, sizeof(random));

		auto tempBlockLen = dataLen + sizeof(random);
		std::unique_ptr<byte[]> memBlock = std::make_unique<byte[]>(tempBlockLen);
		memcpy(memBlock.get(), random, sizeof(random));
		memcpy(memBlock.get() + sizeof(random), pData, dataLen);

		//Calc sha1
		ArraySource hmac_s(memBlock.get(), tempBlockLen, true,
			new HashFilter(hmac_encryptor,
				new ArraySink(sha1, sizeof(sha1))
			)
		);
		//Form iv
		memcpy(iv, sha1, sizeof(iv) - sizeof(random));

		//Encrypt iv using aes256-ecb
		ArraySource ecb_s(iv, sizeof(iv), true,
			new StreamTransformationFilter(m_AesEcbEncryptor,
				new ArraySink((byte*)pDest, destLen),
				BlockPaddingSchemeDef::NO_PADDING
			)
		);
		//Encrypt plainData using aes256-cbc
		m_AesCbcEncryptor.SetKeyWithIV(m_Aes256Key, 32, iv);
		ArraySource cbc_s((const byte*)pData, dataLen, true,
			new StreamTransformationFilter(m_AesCbcEncryptor,
				new ArraySink((byte*)pDest + 16, destLen - 16),
				BlockPaddingSchemeDef::PKCS_PADDING
			)
		);

		return totalSize;
	}

	//Return plain text length
	size_t SymmetricDecryptWithHMACIV(const char* pData, size_t dataLen, char* pDest, size_t destLen, bool checkHmac = true)
	{
		//Decrypt first 16 bytes encrypted iv
		byte iv[16];
		ArraySource ecb_s((byte*)pData, 16, true,
			new StreamTransformationFilter(m_AesEcbDecryptor,
				new ArraySink(iv, sizeof(iv)),
				BlockPaddingSchemeDef::NO_PADDING
			)
		);
		//Decrypt cipher encrypted using aes256-cbc
		m_AesCbcDecryptor.SetKeyWithIV(m_Aes256Key, 32, iv);
		ArraySource cbc_s((byte*)(pData + 16), dataLen - 16, true,
			new StreamTransformationFilter(m_AesCbcDecryptor,
				new ArraySink((byte*)pDest, destLen),
				BlockPaddingSchemeDef::PKCS_PADDING
			)
		);

		//PKCS padding rule
		auto paddingNum = pDest[dataLen - 16 - 1];
		auto plainTextLength = dataLen - 16 - paddingNum;

		if (!checkHmac)
			return plainTextLength;

		//Check if the HMAC part was correct
		byte sha1[20];
		auto tempBlockLen = plainTextLength + 3;
		std::unique_ptr<byte[]> memBlock = std::make_unique<byte[]>(tempBlockLen);
		
		memcpy(memBlock.get(), iv + 13, 3);
		memcpy(memBlock.get() + 3, pDest, plainTextLength);

		HMAC<SHA1> hmac_encryptor(m_Aes256Key, 16);
		ArraySource hmac_s(memBlock.get(), tempBlockLen, true,
			new HashFilter(hmac_encryptor,
				new ArraySink(sha1, sizeof(sha1))
			)
		);

		if (memcmp(iv, sha1, sizeof(iv) - 3) == 0)
		{
			return plainTextLength;
		}
		else
		{
			printf("HMAC Verification Failed!\n");
			return 0;
		}
	}

	void DecompressGzipStream(const char* pData, size_t dataLen, char* pDest, size_t destLen)
	{
		ArraySource as((byte*)pData, dataLen, true,
			new Gunzip(
				new ArraySink((byte*)pDest, destLen)
			)
		);
	}

	uint32_t CalculateCRC32(const char* pData, size_t length)
	{
		return CRC32_ProcessSingleBuffer(pData, length);
	}

	inline void GenerateRandomBytes(byte* pData, size_t dataLen)
	{
		m_RandomPool.GenerateBlock(pData, dataLen);
	}

	inline size_t RSACipherLength(size_t dataLen)
	{
		return m_RsaEncryptor.CiphertextLength(dataLen);
	}

	inline void PrintHexBuffer(void* pData, size_t len)
	{
		for (size_t i = 0; i < len; ++i)
		{
			printf("%02X ", ((uint8_t*)pData)[i] & 0xFF);
		}
		printf("\n");
	}
	
	inline byte* GetAesKey()
	{
		return m_Aes256Key;
	}

	inline size_t GetAesCipherWithHmacLength(int plainTextLength)
	{
		return GetAesCipherLength(plainTextLength) + 16;
	}

private:
	inline size_t GetAesCipherLength(int plainTextLength)
	{
		return (16 - (plainTextLength % 16)) + plainTextLength;
	}

private:
	RandomPool					m_RandomPool;
	RSAES_OAEP_SHA_Encryptor	m_RsaEncryptor;

	CBC_Mode<AES>::Encryption	m_AesCbcEncryptor;
	CBC_Mode<AES>::Decryption	m_AesCbcDecryptor;

	ECB_Mode<AES>::Encryption	m_AesEcbEncryptor;
	ECB_Mode<AES>::Decryption	m_AesEcbDecryptor;

	byte						m_Aes256Key[32];
};

inline static SteamEncryptedChannel s_SteamEncryptedChannel;

inline SteamEncryptedChannel& GetCryptoTool()
{
	return s_SteamEncryptedChannel;
}

inline void InitializeCryptoTool()
{
	s_SteamEncryptedChannel.Init();
}


#endif // !__TINY_STEAM_CLIENT_STEAMENCRYPTEDCHANNEL_HPP__
