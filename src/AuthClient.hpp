#ifndef __TINY_STEAM_CLIENT_TESTCLIENT_HPP
#define __TINY_STEAM_CLIENT_TESTCLIENT_HPP

#include <mutex>
#include <queue>
#include <asio.hpp>
#include "argparser.hpp"
#include "bitbuf/bitbuf.h"
#include "BasicIO.hpp"

#define A2S_GETCHALLENGE		'q'	
#define	S2C_CONNECTION			'B'

using namespace asio::ip;
using namespace std::chrono_literals;

inline asio::io_context s_IoContext;

//Thread safe ticket holder
class TSTicketHolder
{
public:
	void WriteTicket(const char* pData, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_TicketLock);
		m_TicketQueue.push(std::string{ pData, size });
	}

	std::string ReadTicket()
	{
		std::lock_guard<std::mutex> lock(m_TicketLock);
		auto str = m_TicketQueue.front();
		m_TicketQueue.pop();
		return str;
	}

	bool IsQueueEmpty()
	{
		return m_TicketQueue.size() == 0;
	}

private:
	std::mutex				m_TicketLock;
	std::queue<std::string> m_TicketQueue;
};

inline static TSTicketHolder s_TicketHolder;

inline TSTicketHolder& GetTicketHolder()
{
	return s_TicketHolder;
}

class AuthClient
{
public:
	AuthClient(ArgParser& parser) : m_Parser(parser)
	{
	}

	inline void					RunClient()
	{
		s_IoContext.reset();
		asio::co_spawn(s_IoContext, WaitForNewTicket(), asio::detached);
		s_IoContext.run();
	}

private:

	asio::awaitable<void>		WaitForNewTicket()
	{
		while (true)
		{
			asio::steady_timer timer(s_IoContext, 1s);
			co_await timer.async_wait(asio::use_awaitable);

			if (GetTicketHolder().IsQueueEmpty())
				continue;

			co_await ConnectToServer();
		}
	}

	asio::awaitable<void>		ConnectToServer()
	{
		auto* ip = m_Parser.GetOptionValueString("-sip");
		auto port = m_Parser.GetOptionValueInt16U("-sport");

		udp::socket socket(s_IoContext, udp::endpoint(udp::v4(), 0));
		m_GameServerEdp = udp::endpoint(make_address(ip), port);

		auto ticket = GetTicketHolder().ReadTicket();
		auto steamid = *reinterpret_cast<uint64_t*>((uintptr_t)ticket.c_str() + 12);

		criticalmsg("[%llu]Connecting to tiny-csgo-server %s:%d to authenticate new ticket\n", steamid, ip, port);
		co_await SendConnectPacket(socket, ticket, steamid);
	}

	asio::awaitable<void>		SendConnectPacket(udp::socket& socket, const std::string& ticket, uint64_t steamid)
	{
		char temp[2048];
		bf_write writer(temp, sizeof(temp));

		writer.WriteLong(-1);
		writer.WriteByte(A2S_GETCHALLENGE);
		writer.WriteString("tiny-csgo-client");

		writer.WriteShort(ticket.size());
		writer.WriteBytes(ticket.c_str(), ticket.size());

		try
		{
			co_await socket.async_send_to(asio::buffer(temp, writer.GetNumBytesWritten()), m_GameServerEdp, asio::use_awaitable);
		}
		catch (const std::exception& e) 
		{
			printf(e.what());
		}

		asio::steady_timer timer(s_IoContext, 3s);
		asio::co_spawn(s_IoContext,
			[=, this, &socket, &timer]() -> asio::awaitable<void> {
				co_await timer.async_wait(asio::use_awaitable);

				thread_local int failed_times = 0;

				if (failed_times++ < 30)
				{
					criticalmsg("[%llu]Recv time out! resending...\n", steamid);
					co_await SendConnectPacket(socket, ticket, steamid);
					co_return;
				}
				
			},
			asio::detached
		);
		//Wait for auth response
		co_await socket.async_wait(socket.wait_read, asio::use_awaitable);
		co_await socket.async_receive_from(asio::buffer(temp), m_GameServerEdp, asio::use_awaitable);
		timer.cancel();

		bf_read reader(temp, sizeof(temp));
		reader.ReadLong();
		thread_local uint8_t retry = 0;
		if (reader.ReadByte() != S2C_CONNECTION)
		{
			criticalmsg("[%llu]Auth ticket failed\n", steamid);

			//Maybe because of connection lost we're still authenticated
			if (retry++ < 10)
			{
				co_await timer.async_wait(asio::use_awaitable);
				co_await SendConnectPacket(socket, ticket, steamid);
				co_return;
			}
			else
			{
				socket.close();
				co_return;
			}
		}

		criticalmsg("[%llu]Successfully connect to tiny csgo server, close this program will cause ticket being calcelled.\n", steamid);
		retry = 0;
		socket.close();
		co_return;
	}

private:
	ArgParser		m_Parser;
	udp::endpoint	m_GameServerEdp;
};


#endif // !__TINY_STEAM_CLIENT_TESTCLIENT_HPP
