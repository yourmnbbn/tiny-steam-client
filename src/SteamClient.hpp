#ifndef __TINY_STEAM_CLIENT_STEAMCLIENT_HPP__
#define __TINY_STEAM_CLIENT_STEAMCLIENT_HPP__

#include <chrono>
#include <queue>
#include <ctime>
#include <asio.hpp>
#include "argparser.hpp"
#include "SteamEncryptedChannel.hpp"
#include "bitbuf/bitbuf.h"
#include "consts/logonresult.hpp"
#include "proto/steammessages_clientserver_login.pb.h"
#include "proto/steammessages_clientserver.pb.h"
#include "proto/enums_clientserver.pb.h"
#include "steam/steamclientpublic.h"

using namespace asio::ip;

inline asio::io_context g_IoContext;

inline constexpr auto MAGIC						= 0x31305456;
inline constexpr auto AES_KEY_LENGTH			= 32;
inline constexpr auto PROTO_MASK				= (1 << 31);

inline constexpr auto CLIENT_PROTOCOL_VERSION	= 65580;

class SteamClient;

class NetMsgHandler
{
public:
	static void SetSteamClientPtr(SteamClient* cl) { m_pSteamClient = cl; }
	static asio::awaitable<void> HandleMessage(tcp::socket& socket, uint32_t type, void* pData, size_t dataLen);
private:
	template<typename MsgObjType>
	static MsgObjType protomsg_cast(const void* data, size_t length);
private:
	static SteamClient* m_pSteamClient;
};

class SteamClient
{
	friend class NetMsgHandler;
public:
	SteamClient(ArgParser parser) :
		m_Writer(m_WriteBuf, sizeof(m_WriteBuf)), 
		m_Parser(parser)
	{
		NetMsgHandler::SetSteamClientPtr(this);
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
		if (proto_index != k_EMsgChannelEncryptRequest)
		{
			printf("Expect protobuf %d but got %d!\n", k_EMsgChannelEncryptRequest, proto_index);
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
		m_Writer.WriteLong(k_EMsgChannelEncryptResponse);
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
		if (proto_index != k_EMsgChannelEncryptResult)
		{
			printf("Expect protobuf %d but got %d!\n", k_EMsgChannelEncryptResult, proto_index);
			co_return;
		}
		
		auto sourceJobID = reader.ReadLongLong();
		auto targetJobID = reader.ReadLongLong();
		auto result = reader.ReadLong();
		if (result != k_EResultOK)
		{
			printf("EncryptChannelResult received failure code %d!\n", result);
			co_return;
		}

		printf("Successfully established encrypted channel with Steam CM server!\n");
		m_TimeWhenConnectedToCM = time(nullptr);

		co_await UserLogon(socket, m_AccountName.c_str(), m_AccountPassWord.c_str());
	}

	asio::awaitable<void> UserLogon(tcp::socket& socket, const char* username, const char* passwd)
	{
		printf("Logging on to steam, account: %s ...\n", username);

		
		CMsgProtoBufHeader header;
		header.set_client_sessionid(0);
		header.set_steamid(0x0110000100000000);
		header.set_jobid_source(-1);
		header.set_jobid_target(-1);

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

		co_await SendMessageToCM(socket, k_EMsgClientLogon, header, logon);
		co_await StartMessageReceiver(socket);
	}

	asio::awaitable<void>	StartMessageReceiver(tcp::socket& socket)
	{
		while (true)
		{
			auto len = co_await socket.async_read_some(asio::buffer(m_ReadBuf, sizeof(m_ReadBuf)), asio::use_awaitable);
			len = co_await DecryptIncommingPacket(len);
			if (len < 0)
			{
				printf("Received error detected!\n");
				continue;
			}

			co_await HandleIncommingPacket(socket, len);
		}
	}

	asio::awaitable<size_t>	DecryptIncommingPacket(size_t length)
	{
		bf_read reader(m_ReadBuf, length);
		auto payloadLength = CheckPacketHeader(reader, length);
		if (payloadLength < 1)
			co_return 0;

		//Decrypt received cipher
		std::unique_ptr<char[]> memBlock = std::make_unique<char[]>(payloadLength);
		auto plainTextLength = GetCryptoTool().SymmetricDecryptWithHMACIV(
			m_ReadBuf + reader.GetNumBytesRead(),
			reader.GetNumBytesLeft(),
			memBlock.get(),
			payloadLength);

		memcpy(m_ReadBuf, memBlock.get(), plainTextLength);
		co_return plainTextLength;
	}

	asio::awaitable<void> HandleIncommingPacket(tcp::socket& socket, size_t length)
	{
		auto eproto = *reinterpret_cast<uint32_t*>(m_ReadBuf) & 0xFFFF;

		//Handle multi message immediately
		if (eproto == k_EMsgMulti)
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

		//Handle login messages here
		auto headerLen = *reinterpret_cast<uint32_t*>(m_ReadBuf + 4);
		if (eproto == k_EMsgClientLogOnResponse)
		{
			CMsgProtoBufHeader logonResponseHdr;
			logonResponseHdr.ParseFromArray(m_ReadBuf + 8, headerLen);
			m_SessionID = logonResponseHdr.client_sessionid();
			m_SteamID = logonResponseHdr.steamid();

			CMsgClientLogonResponse logonResponse;
			logonResponse.ParseFromArray(m_ReadBuf + 8 + headerLen, length - 8 - headerLen);
			auto logonResult = logonResponse.eresult();
			printf("Logon result: %s(%d)\n", s_LogonResult[logonResult], logonResult);

			switch (logonResult)
			{
			case 1:
			{
				m_HeartbeatInterval = logonResponse.heartbeat_seconds();
				m_PublicIP = logonResponse.public_ip().v4();
				
				printf("Generating app auth session ticket...\n");
				//Send request to get csgo's ownership ticket
				CMsgProtoBufHeader header;
				header.set_client_sessionid(m_SessionID);
				header.set_steamid(m_SteamID);
				header.set_jobid_source(1);
				
				CMsgClientGetAppOwnershipTicket getTicket;
				getTicket.set_app_id(730);
				co_await SendMessageToCM(socket, k_EMsgClientGetAppOwnershipTicket, header, getTicket);

				//Start heart beat process
				asio::co_spawn(g_IoContext, HeartbeatHandler(socket), asio::detached);
				break;
			}
			case 85:
			case 63:
				printf("Please turn off steam guard to logon via tiny-steam-client!\n");
				g_IoContext.stop();
				break;
			}
		}

		co_await NetMsgHandler::HandleMessage(socket, eproto, m_ReadBuf + 8 + headerLen, length - 8 - headerLen);
	}

	asio::awaitable<void> HeartbeatHandler(tcp::socket& socket)
	{
		while (true)
		{
			asio::steady_timer timer(g_IoContext, std::chrono::seconds(m_HeartbeatInterval));
			co_await timer.async_wait(asio::use_awaitable);

			CMsgProtoBufHeader header;
			CMsgClientHeartBeat heartbeat;
			co_await SendMessageToCM(socket, k_EMsgClientHeartBeat, header, heartbeat);
		}
	}

	asio::awaitable<void>	SendMessageToCM(tcp::socket& socket, uint32_t type, google::protobuf::Message& header, google::protobuf::Message& msg)
	{
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
	ArgParser& m_Parser;

	char m_WriteBuf[8192];
	char m_ReadBuf[81920];

	bf_write	m_Writer;

	std::string m_CMServerIP;
	uint16_t	m_CMServerPort;

	std::string m_AccountName;
	std::string m_AccountPassWord;

	uint64_t	m_SteamID = 0;
	int32_t		m_SessionID = 0;
	uint32_t	m_HeartbeatInterval = 5;

	//Used for auth session ticket generation
	uint32_t	m_ConnectTimes = 0;
	time_t		m_TimeWhenConnectedToCM;
	uint8_t		m_OwnershipTicket[2048];
	uint32_t	m_OwnershipTicketLength = 0;
	uint32_t	m_PublicIP;
	bool		m_OwnerShipTicketValid = false;
	std::queue<std::string> m_GCTokens;

	tcp::endpoint	m_CMServerEdp;
};

inline SteamClient* NetMsgHandler::m_pSteamClient = nullptr;

template<typename MsgObjType>
inline MsgObjType NetMsgHandler::protomsg_cast(const void* data, size_t length)
{
	MsgObjType obj;
	obj.ParseFromArray(data, length);
	return obj;
}

inline asio::awaitable<void> NetMsgHandler::HandleMessage(tcp::socket& socket, uint32_t type, void* pData, size_t dataLen)
{
	switch (type)
	{
	case k_EMsgClientGetAppOwnershipTicketResponse:
	{
		auto response = protomsg_cast<CMsgClientGetAppOwnershipTicketResponse>(pData, dataLen);
		if (response.eresult() != k_EResultOK)
		{
			printf("Get app owner ship response with failure code %d\n", response.eresult());
			co_return;
		}

		if (response.ticket().size() != 178)
		{
			printf("Got unexpected ownership ticket length:%d", response.ticket().size());
			co_return;
		}

		time_t expiretime = *reinterpret_cast<const uint32_t*>(response.ticket().c_str() + 36);
		auto* tm = gmtime(&expiretime);
		printf("Get app ownership ticket success! Ownership ticket will be expired after %d/%d/%d(Y/M/D)\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);;

		m_pSteamClient->m_OwnerShipTicketValid = true;
		m_pSteamClient->m_OwnershipTicketLength = response.ticket().size();
		memcpy(m_pSteamClient->m_OwnershipTicket, response.ticket().c_str(), response.ticket().size());

		//Form a proper auth session ticket
		auto& token = m_pSteamClient->m_GCTokens.front();
		
		char temp[2048];
		bf_write writer(temp, sizeof(temp));
		writer.WriteLong(token.size());
		writer.WriteBytes(token.c_str(), token.size());
		writer.WriteLong(24);
		writer.WriteLong(1);
		writer.WriteLong(2);
		writer.WriteLong(m_pSteamClient->m_PublicIP);
		writer.WriteLong(0);
		writer.WriteLong((time(nullptr) + token.c_str()[0] - m_pSteamClient->m_TimeWhenConnectedToCM) * 1000);
		writer.WriteLong(++(m_pSteamClient->m_ConnectTimes));
		writer.WriteLong(response.ticket().size());
		writer.WriteBytes(response.ticket().c_str(), response.ticket().size());

		m_pSteamClient->m_GCTokens.pop();

		//So far we just print the ticket
		printf("Following is the generated auth session ticket:\n");
		GetCryptoTool().PrintHexBuffer(temp, writer.GetNumBytesWritten());
		break;
	}
	case k_EMsgClientGameConnectTokens:
	{
		auto tokens = protomsg_cast<CMsgClientGameConnectTokens>(pData, dataLen);
		printf("Received %d game connect tokens\n", tokens.tokens().size());
		for (auto& token : tokens.tokens())
		{
			m_pSteamClient->m_GCTokens.push(token);
		}
		break;
	}
	default:
		printf("Received protobuf %d but we don't have handler for it.\n", type);
		break;
	}

	co_return;
}

#endif // !__TINY_STEAM_CLIENT_STEAMCLIENT_HPP__
