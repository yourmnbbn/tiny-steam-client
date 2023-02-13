#ifndef __TINY_STEAM_CLIENT_STEAMCLIENT_HPP__
#define __TINY_STEAM_CLIENT_STEAMCLIENT_HPP__

#include <asio.hpp>
#include "argparser.hpp"
#include "SteamEncryptedChannel.hpp"
#include "bitbuf/bitbuf.h"
#include "consts/logonresult.hpp"
#include "proto/steammessages_clientserver_login.pb.h"

using namespace asio::ip;

inline asio::io_context g_IoContext;

inline constexpr auto MAGIC = 0x31305456;
inline constexpr auto AES_KEY_LENGTH = 32;

//TODO: Change to a more proper way of defining the protobuf enums and constances
inline constexpr auto EMSG_EncryptChannelRequest	= 0x517;
inline constexpr auto EMSG_EncryptChannelResponse	= 0x518;
inline constexpr auto EMSG_EncryptChannelResult		= 0x519;
inline constexpr auto EMSG_ClientLogon				= 5514;
inline constexpr auto EMSG_ClientLogonResponse		= 751;
inline constexpr auto EMSG_MsgMulti					= 1;
inline constexpr auto EncryptChannelResult_OK		= 1;
inline constexpr auto PROTO_MASK					= (1 << 31);

inline constexpr auto CLIENT_PROTOCOL_VERSION		= 65580;

class SteamClient
{
public:
	SteamClient(ArgParser parser) :
		m_Writer(m_WriteBuf, sizeof(m_WriteBuf)), 
		m_Parser(parser)
	{
	}
public:
	void SetAccount(const char* username, const char* pw)
	{
		m_AccountName = username;
		m_AccountPassWord = pw;
	}

	bool SetCMServer(const char* socketString)
	{
		auto len = strlen(socketString) + 1;
		std::unique_ptr<char[]> memBlock = std::make_unique<char[]>(len);
		auto* pData = memBlock.get();
		memcpy(pData, socketString, len);

		uint32_t index = 0;
		for (index = 0; index < len - 1; ++index)
		{
			if (pData[index] == ':')
				break;
		}

		if (index == len)
		{
			printf("Can't resolve CM Server address: %s\n", socketString);
			return false;
		}

		m_CMServerPort = static_cast<uint16_t>(atoi(pData + index + 1));
		pData[index] = 0;
		m_CMServerIP = pData;

		return true;
	}

	void RunClient()
	{
		g_IoContext.reset();
		asio::co_spawn(g_IoContext, EstablishEncryptedHandshake(), asio::detached);
		g_IoContext.run();
	}

private:
	asio::awaitable<void>	EstablishEncryptedHandshake()
	{
		printf("Trying to establish connection with CM server %s:%d\n", m_CMServerIP.c_str(), m_CMServerPort);

		tcp::socket socket(g_IoContext);
		
		m_CMServerEdp = tcp::endpoint(make_address(m_CMServerIP), m_CMServerPort);

		co_await socket.async_connect(m_CMServerEdp, asio::use_awaitable);
		auto len = co_await socket.async_read_some(asio::buffer(m_ReadBuf, sizeof(m_ReadBuf)), asio::use_awaitable);
		bf_read reader(m_ReadBuf, len);

		auto payloadLength = CheckPacketHeader(reader, len);
		if (payloadLength < 1)
			co_return;

		auto proto_index = reader.ReadLong();
		if (proto_index != EMSG_EncryptChannelRequest)
		{
			printf("Expect protobuf %d but got %d!\n", EMSG_EncryptChannelRequest, proto_index);
			co_return;
		}

		auto sourceJobID = reader.ReadLongLong();
		auto targetJobID = reader.ReadLongLong();
		auto protocol = reader.ReadLong();
		auto universe = reader.ReadLong();
		printf("CM Server wants to establish encrypted channel\nSource job id: %llx, target job id: %llx, protocol: %d, universe: %d\n",
			sourceJobID, targetJobID, protocol, universe);

		auto randomChallengeLength = reader.GetNumBytesLeft();
		auto encryptedBlockLength = AES_KEY_LENGTH + randomChallengeLength;
		
		//Form plain text block
		std::unique_ptr<char[]> plainTextBlock = std::make_unique<char[]>(encryptedBlockLength);
		memcpy(plainTextBlock.get(), GetCryptoTool().GetAesKey(), AES_KEY_LENGTH);
		memcpy(plainTextBlock.get() + AES_KEY_LENGTH, m_ReadBuf + reader.GetNumBytesRead(), randomChallengeLength);

		//encrypt AES256 key with the RSA public key
		auto cipherLen = GetCryptoTool().RSACipherLength(encryptedBlockLength);
		std::unique_ptr<char[]> cipherMem = std::make_unique<char[]>(cipherLen);
		GetCryptoTool().RSAEncrypt(plainTextBlock.get(), encryptedBlockLength, cipherMem.get(), cipherLen);

		auto crc32 = GetCryptoTool().CalculateCRC32(cipherMem.get(), cipherLen);

		//Form encrypt channel response
		m_Writer.WriteLong(36 + cipherLen);
		m_Writer.WriteLong(MAGIC);
		m_Writer.WriteLong(EMSG_EncryptChannelResponse);
		m_Writer.WriteLongLong(sourceJobID);
		m_Writer.WriteLongLong(targetJobID);
		m_Writer.WriteLong(protocol);
		m_Writer.WriteLong(cipherLen);
		m_Writer.WriteBytes(cipherMem.get(), cipherLen);
		m_Writer.WriteLong(crc32);
		m_Writer.WriteLong(0);

		co_await socket.async_write_some(asio::buffer(m_WriteBuf, m_Writer.GetNumBytesWritten()), asio::use_awaitable);
		co_await ProcessEncryptedChannelResult(socket);
	}

	asio::awaitable<void> ProcessEncryptedChannelResult(tcp::socket& socket)
	{
		auto len = co_await socket.async_read_some(asio::buffer(m_ReadBuf), asio::use_awaitable);
		bf_read reader(m_ReadBuf, len);

		auto payloadLength = CheckPacketHeader(reader, len);
		if (payloadLength < 1)
			co_return;

		auto proto_index = reader.ReadLong();
		if (proto_index != EMSG_EncryptChannelResult)
		{
			printf("Expect protobuf %d but got %d!\n", EMSG_EncryptChannelResult, proto_index);
			co_return;
		}
		
		auto sourceJobID = reader.ReadLongLong();
		auto targetJobID = reader.ReadLongLong();
		auto result = reader.ReadLong();
		if (result != EncryptChannelResult_OK)
		{
			printf("EncryptChannelResult received failure code %d!\n", result);
			co_return;
		}

		printf("Successfully established encrypted channel with Steam CM server!\n");
		co_await UserLogon(socket, m_AccountName.c_str(), m_AccountPassWord.c_str());
	}

	asio::awaitable<void> UserLogon(tcp::socket& socket, const char* username, const char* passwd)
	{
		printf("Logging on to steam, account: %s ...\n", username);

		//TODO: Form a more proper logon message here
		CMsgClientLogon logon;
		logon.set_account_name(username);
		logon.set_password(passwd);
		logon.set_protocol_version(CLIENT_PROTOCOL_VERSION);
		logon.set_cell_id(0);
		logon.set_client_package_version(1771);
		logon.set_supports_rate_limit_response(true);
		logon.set_should_remember_password(false);
		logon.set_steam2_ticket_request(0);

		co_await SendMessageToCM(socket, EMSG_ClientLogon, logon);
		auto len = co_await socket.async_read_some(asio::buffer(m_ReadBuf, sizeof(m_ReadBuf)), asio::use_awaitable);

		co_await DecryptIncommingPacket(socket, len);
	}

	asio::awaitable<void>	DecryptIncommingPacket(tcp::socket& socket, size_t length)
	{
		bf_read reader(m_ReadBuf, length);
		auto payloadLength = CheckPacketHeader(reader, length);
		if (payloadLength < 1)
			co_return;

		//Decrypt received cipher
		std::unique_ptr<char[]> memBlock = std::make_unique<char[]>(payloadLength);
		auto plainTextLength = GetCryptoTool().SymmetricDecryptWithHMACIV(
			m_ReadBuf + reader.GetNumBytesRead(),
			reader.GetNumBytesLeft(),
			memBlock.get(),
			payloadLength);

		memcpy(m_ReadBuf, memBlock.get(), plainTextLength);
		co_await HandleIncommingPacket(socket, plainTextLength);
	}

	asio::awaitable<void> HandleIncommingPacket(tcp::socket& socket, size_t length)
	{
		auto eproto = *reinterpret_cast<uint32_t*>(m_ReadBuf) & 0xFFFF;
		
		//TODO: Handle multi message elsewhere
		if (eproto == EMSG_MsgMulti)
		{
			CMsgMulti multi;
			multi.ParseFromArray(m_ReadBuf + 8, length - 8); //skip proto index and header length

			auto unzippedSize = multi.size_unzipped();
			if (unzippedSize > 0)
			{
				std::unique_ptr<char[]> memBlock = std::make_unique<char[]>(unzippedSize);

				GetCryptoTool().DecompressGzipStream(
					multi.message_body().c_str(),
					multi.message_body().size(),
					memBlock.get(),
					unzippedSize
				);

				bf_read reader(memBlock.get(), unzippedSize);

				//Multiple protobuf in a sigle message
				while (true)
				{
					auto size = reader.ReadLong();
					if (reader.IsOverflowed())
						break;

					reader.ReadBytes(m_ReadBuf, size);
					co_await HandleIncommingPacket(socket, size);
				}

				co_return;
			}

			auto* payload = multi.message_body().c_str();
			auto realMsgLen = *reinterpret_cast<const uint32_t*>(payload);

			memcpy(m_ReadBuf, (void*)(payload + 4), realMsgLen); //skip the size bytes
			co_await HandleIncommingPacket(socket, realMsgLen);
			co_return;
		}

		if (eproto != EMSG_ClientLogonResponse)
		{
			printf("For now we don't handler for (%d)\t%s\n", eproto, GetProtobufNameFromIndex(eproto));
			co_return;
		}

		//TODO: Properly handle CMsgClientLogonResponse and handle elsewhere
		auto headerLen = *reinterpret_cast<uint32_t*>(m_ReadBuf + 4);
		
		CMsgClientLogonResponse logonResponse;
		logonResponse.ParseFromArray(m_ReadBuf + 8 + headerLen, length - 8 - headerLen);

		auto logonResult = logonResponse.eresult();
		printf("Logon result: %s(%d)\n", s_LogonResult[logonResult], logonResult);

		switch (logonResult)
		{
		case 1: 
			printf("Logon success!\n");
			break;
		case 85:
		case 63:
			printf("Please turn off steam guard to logon via tiny-steam-client!\n");
			break;
		}
	}

	asio::awaitable<void>	SendMessageToCM(tcp::socket& socket, uint32_t type, google::protobuf::Message& msg)
	{
		//TODO: Don't hardcode these
		CMsgProtoBufHeader header;
		header.set_client_sessionid(0);
		header.set_steamid(0x0110000100000000); //TODO: Properly generate steamid.
		header.set_jobid_source(-1);
		header.set_jobid_target(-1);

		auto headerLen = header.ByteSize();
		auto msgLen = headerLen + 8 + msg.ByteSize();
		std::unique_ptr<char[]> msgBlock = std::make_unique<char[]>(msgLen);

		bf_write writer(msgBlock.get(), msgLen);

		writer.WriteLong(type | PROTO_MASK);
		writer.WriteLong(headerLen);

		auto numBytesWritten = writer.GetNumBytesWritten();
		header.SerializeToArray(msgBlock.get() + numBytesWritten, msgLen - numBytesWritten);
		msg.SerializeToArray(msgBlock.get() + headerLen + numBytesWritten, msgLen - headerLen - numBytesWritten);
		
		auto cipherLen = GetCryptoTool().GetAesCipherWithHmacLength(msgLen);
		m_Writer.Reset();
		m_Writer.WriteLong(cipherLen);
		m_Writer.WriteLong(MAGIC);

		GetCryptoTool().SymmetricEncryptWithHMACIV(msgBlock.get(), msgLen, m_WriteBuf + m_Writer.GetNumBytesWritten(), sizeof(m_WriteBuf) - m_Writer.GetNumBytesWritten());
		co_await socket.async_write_some(asio::buffer(m_WriteBuf, m_Writer.GetNumBytesWritten() + cipherLen), asio::use_awaitable);
	}

public:
	size_t CheckPacketHeader(bf_read& reader, size_t length)
	{
		auto payloadLength = reader.ReadLong();
		if (reader.ReadLong() != MAGIC)
		{
			printf("Packet magic mismatch!\n");
			return 0;
		}

		if (payloadLength != length - reader.GetNumBytesRead())
		{
			printf("Packet payload length mismatch!(%d/%d)\n", payloadLength, length - reader.GetNumBytesRead());
			return 0;
		}

		return payloadLength;
	}

private:
	//TODO: This demo function will be deleted in the future
	const char* GetProtobufNameFromIndex(int index)
	{
		switch (index)
		{
		case 5501:	return "ClientServersAvailable";
		case 768:	return "ClientAccountInfo";
		case 5456:	return "ClientEmailAddrInfo";
		case 767:	return "ClientFriendsList";
		case 5587:	return "ClientPlayerNicknameList";
		case 780:	return "ClientLicenseList";
		case 798:	return "ClientUpdateGuestPassesList";
		case 5528:	return "ClientWalletInfoUpdate";
		case 779:	return "ClientGameConnectTokens";
		case 783:	return "ClientCMList";
		case 5480:	return "ClientRequestedClientStats";
		case 9600:	return "ClientPlayingSessionState";
		case 782:	return "ClientVACBanStatus";
		case 5430:	return "ClientIsLimitedAccount";
		case 5537:	return "ClientUpdateMachineAuth";
		default:
			return "UnknownForNow";
		}
	}

private:
	ArgParser& m_Parser;

	char m_WriteBuf[8192];
	char m_ReadBuf[81920];

	bf_write	m_Writer;

	std::string m_CMServerIP;
	uint16_t	m_CMServerPort;

	std::string m_AccountName;
	std::string m_AccountPassWord;

	tcp::endpoint	m_CMServerEdp;
};


#endif // !__TINY_STEAM_CLIENT_STEAMCLIENT_HPP__
