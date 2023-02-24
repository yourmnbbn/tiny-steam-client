#ifndef __TINY_STEAM_CLIENT_BASICIO_HPP__
#define __TINY_STEAM_CLIENT_BASICIO_HPP__

#include <cstdarg>
#include <cstdio>

//When we maintain many accounts we only want critical information to be printed
#define IGNORE_DBG_MESSAGE

//Print debug message
inline int dbgmsg(const char* format, ...)
{
#ifndef IGNORE_DBG_MESSAGE
	va_list args;
	va_start(args, format);
	int count = vfprintf(stdout, format, args);
	va_end(args);
	return count;
#else	
	return 0;
#endif // IGNORE_DBG_MESSAGE
}

//Print critical messages
inline int criticalmsg(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	int count = vfprintf(stdout, format, args);
	va_end(args);
	return count;
}

#endif // !__TINY_STEAM_CLIENT_BASICIO_HPP__
