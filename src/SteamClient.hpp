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
#include "proto/steammessages_clientserver_2.pb.h"
#include "proto/steammessages_clientserver_friends.pb.h"
#include "proto/enums_clientserver.pb.h"
#include "steam/steamclientpublic.h"
#include "WebApiHelper.hpp"
#include "AuthClient.hpp"

using namespace asio::ip;
using namespace std::chrono_literals;

inline asio::io_context g_IoContext;

inline constexpr auto MAGIC						= 0x31305456;
inline constexpr auto AES_KEY_LENGTH			= 32;
inline constexpr auto PROTO_MASK				= (1 << 31);
inline constexpr auto APP_ID					= 730;

inline constexpr auto CLIENT_PROTOCOL_VERSION	= 65580;

class SteamClient;

//-----------------------------------------------------------------
//               Definition of NetMsgHandler
//-----------------------------------------------------------------
class NetMsgHandler
{
public:
	void SetSteamClientPtr(SteamClient* cl) { m_pSteamClient = cl; }
	asio::awaitable<void> HandleMessage(tcp::socket& socket, uint32_t type, void* pData, size_t dataLen);
private:
	template<typename MsgObjType>
	static MsgObjType protomsg_cast(const void* data, size_t length);
private:
	SteamClient* m_pSteamClient = nullptr;
};

//-----------------------------------------------------------------
//               Definition of SteamClient
//-----------------------------------------------------------------
class SteamClient
{
	friend class NetMsgHandler;

	enum ConnectionState
	{
		kE_NoConnection,
		kE_ConnectedWithoutEncryptedChannel,
		kE_ConnectedWithEncryptedChannel,
	};

public:
	SteamClient(const char* username, const char* passwd, const char* tfc, const char* ac)
	{
		SetAccount(username, passwd, tfc, ac);
	}
public:
	void SetAccount(const char* username, const char* pw, const char* twofactor = "", const char* authcode = "")
	{
		m_AccountName = username;
		m_AccountPassWord = pw;
		m_TwoFactorCode = twofactor;
		m_SteamAuthCode = authcode;
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
			criticalmsg("Can't resolve CM Server address: %s\n", socketString);
			return false;
		}

		m_CMServerPort = static_cast<uint16_t>(atoi(pData + index + 1));
		pData[index] = 0;
		m_CMServerIP = pData;

		return true;
	}

	void PrepareNetwork() 
	{ 
		asio::co_spawn(g_IoContext, ConnectToCM(), asio::detached); 
	}

protected:
	asio::awaitable<void>	ConnectToCM()
	{
		while (true)
		{
			//When the code reaches here again, meaning there is something wrong with the previous connection, reconnect.
			asio::steady_timer timer(g_IoContext, 3s);
			co_await timer.async_wait(asio::use_awaitable);

			if (!SteamWebApiHelper::CheckCachedCMList())
				continue;

			auto svsocket = SteamWebApiHelper::GetPickedCMServer();
			SetCMServer(svsocket.c_str());

			tcp::socket socket(g_IoContext);
			co_await EstablishEncryptedHandshake(socket);
			socket.close();
		}
	}

private:
	asio::awaitable<void>	EstablishEncryptedHandshake(tcp::socket& socket)
	{
		criticalmsg("[%s]Trying to establish connection with CM server %s:%d\n", m_AccountName.c_str(), m_CMServerIP.c_str(), m_CMServerPort);

		m_CMServerEdp = tcp::endpoint(make_address(m_CMServerIP), m_CMServerPort);
		
		try
		{
			co_await socket.async_connect(m_CMServerEdp, asio::use_awaitable);
		}
		catch (const std::exception& e)
		{
			criticalmsg("[%s]Can't connect to %s:%d(%s), change a cm server\n",
				m_AccountName.c_str(),
				m_CMServerIP.c_str(),
				m_CMServerPort,
				e.what()
			);
				
			std::this_thread::sleep_for(3s);
			co_return;
		}
		
		m_ConnectionState = kE_ConnectedWithoutEncryptedChannel;
		auto len = co_await ReceiveSingleFrame(socket);
		if (len < 1)
			co_return;

		bf_read reader(m_ReadBuf, len);
		auto payloadLength = CheckPacketHeader(reader, len);
		if (payloadLength < 1)
			co_return;

		auto proto_index = reader.ReadLong();
		if (proto_index != k_EMsgChannelEncryptRequest)
		{
			dbgmsg("Expect protobuf %d but got %d!\n", k_EMsgChannelEncryptRequest, proto_index);
			co_return;
		}

		auto sourceJobID = reader.ReadLongLong();
		auto targetJobID = reader.ReadLongLong();
		auto protocol = reader.ReadLong();
		auto universe = reader.ReadLong();
		dbgmsg("CM Server wants to establish encrypted channel\nSource job id: %llx, target job id: %llx, protocol: %d, universe: %d\n",
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

		//Temp fix for multi instances error
		char temp[2048];
		bf_write writer(temp, sizeof(temp));

		//Form encrypt channel response
		writer.Reset();
		writer.WriteLong(36 + cipherLen);
		writer.WriteLong(MAGIC);
		writer.WriteLong(k_EMsgChannelEncryptResponse);
		writer.WriteLongLong(sourceJobID);
		writer.WriteLongLong(targetJobID);
		writer.WriteLong(protocol);
		writer.WriteLong(cipherLen);
		writer.WriteBytes(cipherMem.get(), cipherLen);
		writer.WriteLong(crc32);
		writer.WriteLong(0);
		
		co_await SendRawData(socket, temp, writer.GetNumBytesWritten());
		co_await ProcessEncryptedChannelResult(socket);
		co_return;
	}

	asio::awaitable<void> ProcessEncryptedChannelResult(tcp::socket& socket)
	{
		auto len = co_await ReceiveSingleFrame(socket);
		if (len < 1)
			co_return;

		bf_read reader(m_ReadBuf, len);

		auto payloadLength = CheckPacketHeader(reader, len);
		if (payloadLength < 1)
			co_return;

		auto proto_index = reader.ReadLong();
		if (proto_index != k_EMsgChannelEncryptResult)
		{
			dbgmsg("Expect protobuf %d but got %d!\n", k_EMsgChannelEncryptResult, proto_index);
			co_return;
		}
		
		auto sourceJobID = reader.ReadLongLong();
		auto targetJobID = reader.ReadLongLong();
		auto result = reader.ReadLong();
		if (result != k_EResultOK)
		{
			dbgmsg("EncryptChannelResult received failure code %d!\n", result);
			co_return;
		}

		criticalmsg("[%s]Successfully established encrypted channel with Steam CM server!\n", m_AccountName.c_str());
		m_TimeWhenConnectedToCM = time(nullptr);
		m_ConnectionState = kE_ConnectedWithEncryptedChannel;

		co_await UserLogon(socket, m_AccountName.c_str(), m_AccountPassWord.c_str());
	}

	asio::awaitable<void> UserLogon(tcp::socket& socket, const char* username, const char* passwd)
	{
		criticalmsg("Logging on to steam, account: %s ...\n", username);
		
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

		if(!m_TwoFactorCode.empty())
			logon.set_two_factor_code(m_TwoFactorCode.c_str());
		if(!m_SteamAuthCode.empty())
			logon.set_auth_code(m_SteamAuthCode.c_str());

		co_await SendMessageToCM(socket, k_EMsgClientLogon, header, logon);
		co_await StartMessageReceiver(socket);
	}

	asio::awaitable<void>	StartMessageReceiver(tcp::socket& socket)
	{
		while (true)
		{
			if (m_ConnectionState != kE_ConnectedWithEncryptedChannel)
				co_return;

			asio::steady_timer timer(g_IoContext, 1s);
			co_await timer.async_wait(asio::use_awaitable);

			auto len = co_await ReceiveSingleFrame(socket);
			if (len < 1)
				co_return;

			len = co_await DecryptIncommingPacket(len);
			if (len < 0)
			{
				dbgmsg("Received error detected!\n");
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

		try
		{
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
		catch (const std::exception& e)
		{
			dbgmsg("Decryption error! %s\n", e.what());
			co_return 0;
		}
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
			criticalmsg("[%s][%llu]Logon result: %s(%d)\n", m_AccountName.c_str(), m_SteamID, s_LogonResult[logonResult], logonResult);

			switch (logonResult)
			{
			case 1:
			{
				m_HeartbeatInterval = logonResponse.heartbeat_seconds();
				m_PublicIP = logonResponse.public_ip().v4();

				CMsgProtoBufHeader header;
				header.set_client_sessionid(m_SessionID);
				header.set_steamid(m_SteamID);
				
				//Tell steam that we are online
				CMsgClientChangeStatus status;
				status.set_persona_state(1);
				co_await SendMessageToCM(socket, k_EMsgClientChangeStatus, header, status);

				//Start heart beat process
				asio::co_spawn(g_IoContext, HeartbeatHandler(socket), asio::detached);
				break;
			}
			case 85:
				criticalmsg("Please enter yout two factor code using command-line option -tfc\n");
				g_IoContext.stop();
				break;
			case 63:
				criticalmsg("Please enter your steam auth code in your email using command-line option -ac\n");
				g_IoContext.stop();
				break;
			}

			co_return;
		}

		m_MsgHandler.SetSteamClientPtr(this);
		co_await m_MsgHandler.HandleMessage(socket, eproto, m_ReadBuf + 8 + headerLen, length - 8 - headerLen);
	}

	asio::awaitable<void> RequestAppAuthSessionTicket(tcp::socket& socket, uint32_t appid)
	{
		if (m_GCTokens.size() < 1)
		{
			criticalmsg("Generating auth session ticket for app %u failed! Not enough valid gc tokens\n", appid);
			co_return;
		}

		//Tell steam that we are playing the game
		auto header = FormProtobufMsgHeader();
		CMsgClientGamesPlayed games;
		auto* game = games.add_games_played();
		game->set_game_id(appid);
		co_await SendMessageToCM(socket, k_EMsgClientGamesPlayed, header, games);

		char filename[64];
		snprintf(filename, sizeof(filename), "ownership_%llu_%u.bin", m_SteamID, appid);

		std::ifstream file(filename, std::ifstream::in | std::ifstream::binary | std::ifstream::ate);
		auto fileLen = file.tellg();
		if (fileLen < 1)
		{
			file.close();
			criticalmsg("Can't find cached app %u ownership ticket for %llu\nRequesting from steam...\n", appid, m_SteamID);
			co_await RequestOwnershipTicketFromSteam(socket, appid);
			co_return;
		}

		file.seekg(0);
		file.read((char*)m_OwnershipTicket, fileLen);
		file.close();

		time_t expiretime = *reinterpret_cast<const uint32_t*>(m_OwnershipTicket + 36);
		if (expiretime < time(nullptr))
		{
			criticalmsg("Cached app %u ownership ticket for %llu is expired\nRequesting from steam...\n", appid, m_SteamID);
			co_await RequestOwnershipTicketFromSteam(socket, appid);
			co_return;
		}

		m_OwnershipTicketLength = fileLen;
		m_OwnerShipTicketValid = true;
		co_await BuildAndActivateAuthSessionTicket(socket, appid);
	}

	asio::awaitable<void> BuildAndActivateAuthSessionTicket(tcp::socket& socket, uint32_t appid)
	{
		//Form a proper auth session ticket
		auto& token = m_GCTokens.front();

		bf_write writer(m_AppAuthSessionTicket, sizeof(m_AppAuthSessionTicket));
		writer.WriteLong(token.size());
		writer.WriteBytes(token.c_str(), token.size());
		writer.WriteLong(24);
		writer.WriteLong(1);
		writer.WriteLong(2);
		writer.WriteLong(m_PublicIP);
		writer.WriteLong(0);
		writer.WriteLong((time(nullptr) + token.c_str()[0] - m_TimeWhenConnectedToCM) * 1000);
		writer.WriteLong(++m_ConnectTimes);
		writer.WriteLong(m_OwnershipTicketLength);
		writer.WriteBytes(m_OwnershipTicket, m_OwnershipTicketLength);

		m_GCTokens.pop();

		m_AppAuthSessionTicketLength = writer.GetNumBytesWritten();

		//print the ticket
		criticalmsg("[%llu]Successfully generated auth session ticket(size %d):\n", m_SteamID, m_AppAuthSessionTicketLength);
		GetCryptoTool().PrintHexBuffer(m_AppAuthSessionTicket, m_AppAuthSessionTicketLength);

		//Send the auth list containing our tick to CM, waiting to be authenticated.
		auto hdr = FormProtobufMsgHeader();
		CMsgClientAuthList list;
		list.add_app_ids(appid);
		list.set_tokens_left(m_GCTokens.size());

		auto* ticket = list.add_tickets();
		ticket->set_estate(0);
		ticket->set_steamid(0);
		ticket->set_gameid(appid);
		ticket->set_h_steam_pipe(m_SessionID * 10 + 5);

		//Only first two ticket section is going to be listed
		ticket->set_ticket_crc(GetCryptoTool().CalculateCRC32((char*)m_AppAuthSessionTicket, 52));
		ticket->set_ticket(m_AppAuthSessionTicket, 52);

		co_await SendMessageToCM(socket, k_EMsgClientAuthList, hdr, list);
		GetTicketHolder().WriteTicket((char*)m_AppAuthSessionTicket, m_AppAuthSessionTicketLength);
	}
	
	asio::awaitable<void> RequestOwnershipTicketFromSteam(tcp::socket& socket, uint32_t appid)
	{
		//Send request to get csgo's ownership ticket
		auto header = FormProtobufMsgHeader();
		header.set_jobid_source(1);

		CMsgClientGetAppOwnershipTicket getTicket;
		getTicket.set_app_id(appid);
		co_await SendMessageToCM(socket, k_EMsgClientGetAppOwnershipTicket, header, getTicket);
	}

	asio::awaitable<void> HeartbeatHandler(tcp::socket& socket)
	{
		while (true)
		{
			if (m_ConnectionState != kE_ConnectedWithEncryptedChannel)
				co_return;

			asio::steady_timer timer(g_IoContext, std::chrono::seconds(m_HeartbeatInterval));
			co_await timer.async_wait(asio::use_awaitable);

			CMsgProtoBufHeader header;
			CMsgClientHeartBeat heartbeat;
			co_await SendMessageToCM(socket, k_EMsgClientHeartBeat, header, heartbeat);
		}
	}

	asio::awaitable<void> SendMessageToGC(tcp::socket& socket, uint32_t type, google::protobuf::Message& msg)
	{
		struct GCMsgHdr_t
		{
			uint32	m_eMsg;					// The message type
			uint32	m_nSrcGCDirIndex;		// The GC index that this message was sent from (set to the same as the current GC if not routed through another GC)
		};

		auto size = msg.ByteSize() + sizeof(GCMsgHdr_t);
		std::unique_ptr<char[]> memBlock = std::make_unique<char[]>(size);

		GCMsgHdr_t* header = (GCMsgHdr_t*)memBlock.get();
		header->m_eMsg = type | PROTO_MASK;
		header->m_nSrcGCDirIndex = 0;

		msg.SerializeToArray(memBlock.get() + sizeof(GCMsgHdr_t), size - sizeof(GCMsgHdr_t));
		co_await SendMessageToGC_Proxy(socket, type, memBlock.get(), size);
	}

	asio::awaitable<void>	SendMessageToGC_Proxy(tcp::socket& socket, uint32_t type, void* pData, size_t length)
	{
		auto hdr = FormProtobufMsgHeader();
		hdr.set_routing_appid(APP_ID);
		
		CMsgGCClient gcclient;
		gcclient.set_appid(APP_ID);
		gcclient.set_msgtype(type | PROTO_MASK);

		gcclient.set_payload(pData, length);

		co_await SendMessageToCM(socket, k_EMsgClientToGC, hdr, gcclient);
	}

	asio::awaitable<void>	SendMessageToCM(tcp::socket& socket, uint32_t type, google::protobuf::Message& header, google::protobuf::Message& msg)
	{
		char temp[4096];
		auto headerLen = header.ByteSize();
		auto msgLen = headerLen + 8 + msg.ByteSize();
		std::unique_ptr<char[]> msgBlock = std::make_unique<char[]>(msgLen);

		bf_write writer(msgBlock.get(), msgLen);
		bf_write finalMsg(temp, sizeof(temp));

		writer.WriteLong(type | PROTO_MASK);
		writer.WriteLong(headerLen);

		auto numBytesWritten = writer.GetNumBytesWritten();
		header.SerializeToArray(msgBlock.get() + numBytesWritten, msgLen - numBytesWritten);
		msg.SerializeToArray(msgBlock.get() + headerLen + numBytesWritten, msgLen - headerLen - numBytesWritten);
		
		auto cipherLen = GetCryptoTool().GetAesCipherWithHmacLength(msgLen);
		finalMsg.Reset();
		finalMsg.WriteLong(cipherLen);
		finalMsg.WriteLong(MAGIC);

		GetCryptoTool().SymmetricEncryptWithHMACIV(msgBlock.get(), msgLen, temp + finalMsg.GetNumBytesWritten(), sizeof(temp) - finalMsg.GetNumBytesWritten());
		co_await SendRawData(socket, temp, finalMsg.GetNumBytesWritten() + cipherLen);
	}

	asio::awaitable<void> SendRawData(tcp::socket& socket, const char* pData, size_t length)
	{
		try
		{
			co_await socket.async_send(asio::buffer(pData, length), asio::use_awaitable);
		}
		catch (const std::exception& e)
		{
			criticalmsg("[%llu]Caught connection exception in SendRawData(%s), reconnecting... \n", m_SteamID, e.what());
			m_ConnectionState = kE_NoConnection;
			
			co_return;
		}
	}

	asio::awaitable<size_t> ReceiveSingleFrame(tcp::socket& socket)
	{
		try
		{
			//First we receive the next packet payload size
			co_await asio::async_read(socket, asio::buffer(m_ReadBuf, 4), asio::use_awaitable);
			auto payloadLength = *(uint32_t*)m_ReadBuf;

			//Read magic(4 bytes) + payload
			co_await asio::async_read(socket, asio::buffer(m_ReadBuf + 4, payloadLength + 4), asio::use_awaitable);
			co_return payloadLength + 8;
		}
		catch (const std::exception& e)
		{
			criticalmsg("[%llu]Caught connection exception in ReceiveSingleFrame(%s), reconnecting... \n", m_SteamID, e.what());
			m_ConnectionState = kE_NoConnection;
			
			co_return 0;
		}
	}
public:
	bool ShouldExit()
	{
		return m_ShouldExit;
	}
private:
	size_t CheckPacketHeader(bf_read& reader, size_t length)
	{
		auto payloadLength = reader.ReadLong();
		if (reader.ReadLong() != MAGIC)
		{
			dbgmsg("Packet magic mismatch!\n");
			return 0;
		}

		if (payloadLength != length - reader.GetNumBytesRead())
		{
			dbgmsg("Packet payload length mismatch!(%d/%d)\n", payloadLength, length - reader.GetNumBytesRead());
			return 0;
		}

		return payloadLength;
	}

	CMsgProtoBufHeader FormProtobufMsgHeader()
	{
		CMsgProtoBufHeader header;
		header.set_steamid(m_SteamID);
		header.set_client_sessionid(m_SessionID);
		return header;
	}

private:
	char m_ReadBuf[12288];

	std::string m_CMServerIP;
	uint16_t	m_CMServerPort;

	std::string m_AccountName;
	std::string m_AccountPassWord;
	std::string m_TwoFactorCode;
	std::string m_SteamAuthCode;

	uint64_t	m_SteamID = 0;
	int32_t		m_SessionID = 0;
	uint32_t	m_HeartbeatInterval = 5;

	ConnectionState	m_ConnectionState = kE_NoConnection;
	bool			m_ShouldExit = false;

	//Used for auth session ticket generation
	uint32_t	m_ConnectTimes = 0;
	time_t		m_TimeWhenConnectedToCM;
	time_t		m_TimeWhenActivateTicket;
	uint8_t		m_OwnershipTicket[2048];
	uint32_t	m_OwnershipTicketLength = 0;
	uint8_t		m_AppAuthSessionTicket[2048];
	uint32_t	m_AppAuthSessionTicketLength = 0;
	uint32_t	m_PublicIP;
	bool		m_OwnerShipTicketValid = false;
	std::queue<std::string> m_GCTokens;

	tcp::endpoint	m_CMServerEdp;
	udp::endpoint	m_GameServerEdp;

	NetMsgHandler	m_MsgHandler;
};


//-----------------------------------------------------------------
//               Definition of SteamClientMgr
//-----------------------------------------------------------------

class SteamClientMgr
{
public:
	SteamClientMgr()
	{
		m_Accounts.reserve(32);
	}
public:
	void AddAccount(const char* user, const char* passwd, const char* tfc = "", const char* ac = "")
	{
		m_Accounts.emplace_back(SteamClient{ user, passwd, tfc, ac });
	}

	void RunClients()
	{
		g_IoContext.reset();

		for (auto& client : m_Accounts)
		{
			client.PrepareNetwork();
		}

		g_IoContext.run();
	}
private:
	std::vector<SteamClient> m_Accounts;
};


//-----------------------------------------------------------------
//               Implementation of NetMsgHandler
//-----------------------------------------------------------------

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
			criticalmsg("[%llu]Get app owner ship response with failure code %d\n", m_pSteamClient->m_SteamID, response.eresult());
			co_return;
		}

		time_t expiretime = *reinterpret_cast<const uint32_t*>(response.ticket().c_str() + 36);
		auto* tm = gmtime(&expiretime);
		criticalmsg("[%llu]Get app ownership ticket success! Ownership ticket will be expired after %d/%d/%d(Y/M/D)\nWriting to file...\n",
			m_pSteamClient->m_SteamID,
			tm->tm_year + 1900, 
			tm->tm_mon + 1, 
			tm->tm_mday
		);

		//Copy to steam client
		m_pSteamClient->m_OwnerShipTicketValid = true;
		m_pSteamClient->m_OwnershipTicketLength = response.ticket().size();
		memcpy(m_pSteamClient->m_OwnershipTicket, response.ticket().c_str(), response.ticket().size());

		//Save the cache to file
		char filename[64];
		snprintf(filename, sizeof(filename), "ownership_%llu_%u.bin", m_pSteamClient->m_SteamID, response.app_id());
		std::ofstream file(filename, std::ofstream::out | std::ofstream::binary);
		file.write(response.ticket().c_str(), response.ticket().size());
		file.close();

		//Build and validate auth session ticket
		co_await m_pSteamClient->BuildAndActivateAuthSessionTicket(socket, response.app_id());
		break;
	}
	case k_EMsgClientGameConnectTokens:
	{
		auto tokens = protomsg_cast<CMsgClientGameConnectTokens>(pData, dataLen);
		dbgmsg("[%llu]Received %d game connect tokens\n", m_pSteamClient->m_SteamID, tokens.tokens().size());
		for (auto& token : tokens.tokens())
		{
			m_pSteamClient->m_GCTokens.push(token);
		}

		//We have to wait for GC tokens to generate auth session ticket, and for now we only generate this once per login session
		if (m_pSteamClient->m_TimeWhenActivateTicket != m_pSteamClient->m_TimeWhenConnectedToCM)
		{
			m_pSteamClient->m_TimeWhenActivateTicket = m_pSteamClient->m_TimeWhenConnectedToCM;
			co_await m_pSteamClient->RequestAppAuthSessionTicket(socket, APP_ID);
		}
		break;
	}
	case k_EMsgClientFromGC:
	{
		auto msg = protomsg_cast<CMsgGCClient>(pData, dataLen);
		if (msg.appid() != APP_ID)
		{
			dbgmsg("Expecting gc message of app %d, but got %d\n", APP_ID, msg.appid());
			break;
		}

		//TODO: Handle gc messages
		auto msgType = msg.msgtype() & 0xFFFF;
		dbgmsg("Got GC message %d\n", msgType);

		break;
	}
	case k_EMsgClientLoggedOff:
	{
		auto msg = protomsg_cast<CMsgClientLoggedOff>(pData, dataLen);
		criticalmsg("[%llu]Log off from steam, reason: (%s)%d\n", m_pSteamClient->m_SteamID, s_LogonResult[msg.eresult()], msg.eresult());
		break;
	}
	case k_EMsgClientAccountInfo:
	{
		auto msg = protomsg_cast<CMsgClientAccountInfo>(pData, dataLen);
		dbgmsg("Username:%s, country: %s\n", msg.persona_name().c_str(), msg.ip_country().c_str());
		break;
	}
	case k_EMsgClientEmailAddrInfo:
	{
		auto msg = protomsg_cast<CMsgClientEmailAddrInfo>(pData, dataLen);
		dbgmsg("Client email %s(validated %s)\n",
			msg.email_address().c_str(),
			msg.email_is_validated() ? "yes" : "no"
		);
		break;
	}
	case k_EMsgClientWalletInfoUpdate:
	{
		auto msg = protomsg_cast<CMsgClientWalletInfoUpdate>(pData, dataLen);
		dbgmsg("Client %s a wallet, currency %d, balance %.2f\n",
			msg.has_wallet() ? "has" : "doesn't have",
			msg.currency(),
			static_cast<float>(msg.balance())/100.F
		);
		break;
	}
	case k_EMsgClientIsLimitedAccount:
	{
		auto msg = protomsg_cast<CMsgClientIsLimitedAccount>(pData, dataLen);
		dbgmsg("Client account limited?(%s), locked?(%s), community banned?(%s)\n",
			msg.bis_limited_account() ? "yes" : "no",
			msg.bis_locked_account() ? "yes" : "no",
			msg.bis_community_banned() ? "yes" : "no"
		);
		break;
	}
	case k_EMsgClientUpdateMachineAuth:
	{
		auto msg = protomsg_cast<CMsgClientUpdateMachineAuth>(pData, dataLen);
		dbgmsg("Got new sentry file, save to sentry.bin\n");

		char filename[64];
		snprintf(filename, sizeof(filename), "sentry_%llu.bin", m_pSteamClient->m_SteamID);

		std::ofstream out(filename, std::ofstream::out | std::ofstream::binary);
		out.write(msg.bytes().c_str(), msg.bytes().size());
		out.close();
		break;
	}
	case k_EMsgClientNewLoginKey:
	{
		dbgmsg("Get a new login key, shall we accept it?\n");
		break;
	}
	case k_EMsgClientPersonaState:
	{
		auto msg = protomsg_cast<CMsgClientPersonaState>(pData, dataLen);
		dbgmsg("Got new persona state flags 0x%X\n", msg.status_flags());
		break;
	}
	case k_EMsgClientAuthListAck:
	{
		dbgmsg("CM Server has received our auth ticket list\n");
		break;
	}
	case k_EMsgClientTicketAuthComplete:
	{
		criticalmsg("[%llu]One of our auth session ticket has been authenticated.\n", m_pSteamClient->m_SteamID);
		break;
	}
	case k_EMsgClientItemAnnouncements:
	{
		auto msg = protomsg_cast<CMsgClientItemAnnouncements>(pData, dataLen);
		dbgmsg("You've got %d new items in your account.\n", msg.count_new_items());
		break;
	}

	//For now we silently drop these first
	case k_EMsgClientChatOfflineMessageNotification:
	case k_EMsgClientClanState:
	case k_EMsgClientServiceCall:
	case k_EMsgServiceMethod:
	case k_EMsgClientFriendsGroupsList:
	case k_EMsgClientVACBanStatus:
	case k_EMsgClientConcurrentSessionsBase:
	case k_EMsgClientRequestedClientStats:
	case k_EMsgClientPlayerNicknameList: //maybe too many, don't display
	case k_EMsgClientFriendsList: //maybe too many, don't display
	case k_EMsgClientServersAvailable:
	case k_EMsgClientLicenseList:
	case k_EMsgClientUpdateGuestPassesList:
		break;
	default:
		dbgmsg("*** Received protobuf %d but we don't have handler for it. ***\n", type);
		break;
	}

	co_return;
}

#endif // !__TINY_STEAM_CLIENT_STEAMCLIENT_HPP__
