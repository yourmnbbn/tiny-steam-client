#ifndef __TINY_STEAM_CLIENT_WEBAPIHELPER_HPP__
#define __TINY_STEAM_CLIENT_WEBAPIHELPER_HPP__

#include <ctime>
#include <fstream>
#include <mutex>
#include "curl/curl.h"
#include "json/json.hpp"
#include "SteamEncryptedChannel.hpp"

inline constexpr auto CM_FILE_NAME = "CMList.cfg";
inline constexpr auto CM_FILE_TIME_FEILD = "time";
inline constexpr auto CM_CACHE_MAX_INTERVAL_DAYS = 10;

using json = nlohmann::json;

class SteamWebApiHelper
{
public:
    static bool CheckCachedCMList()
    {
        printf("Searching for local CM list cache...\n");

        json data;
        {
            std::lock_guard<std::mutex> lock(m_CMListLock);
            std::ifstream cmfile(CM_FILE_NAME, std::ifstream::in | std::ifstream::binary | std::ifstream::ate);
            if (cmfile.tellg() < 1)
            {
                printf("Can't find cached CM list!\n");
                cmfile.close();
                return GetCMList();
            }
            cmfile.seekg(0);

            //Parse cache
            data = json::parse(cmfile);
            cmfile.close();
        }

        //Check time
        auto tm_str = data[CM_FILE_TIME_FEILD].get<std::string>();
        time_t tm;
        sscanf(tm_str.c_str(), "%lli", &tm);
        time_t now = time(nullptr);

        auto interval = now - tm;
        auto* s_tm = gmtime(&interval);
        if (s_tm->tm_yday > CM_CACHE_MAX_INTERVAL_DAYS)
        {
            printf("CM server list cache is outdated!\n");
            //If request failed, we just use the old cache
            if (GetCMList())
                return true;
        }

        return PickCMServerFromJson(data);
    }

    //This has to be called after request or there would be memory leak.
    static std::string& GetPickedCMServer()
    {
        if (m_pData)
            delete[] m_pData;

        return m_CMAddr;
    }

private:
    static bool GetCMList()
    {
        printf("Getting CM list from steam web api...\n");
        CURL* curl;
        CURLcode res;

        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (!curl)
        {
            printf("CURL can't be initialized!\n");
            return false;
        }
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?format=json&cellid=0");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteDataCallback);

        res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        curl_global_cleanup();

        if (res != CURLE_OK)
        {
            printf("Get CM server list error! %s\n", curl_easy_strerror(res));
            return false;
        }

        printf("Get CM server list success!\n");
        return ProcessResource();
    }

    static bool PickCMServerFromJson(json& data)
    {
        auto list = data["response"]["serverlist"];
        auto length = list.size();
        if (length < 1)
        {
            printf("CM server list size is 0 !\n");
            return false;
        }

        //Randomly pick a CM server
        byte rand;
        GetCryptoTool().GenerateRandomBytes(&rand, 1);
        auto index = rand % length;
        m_CMAddr = list[index].get<std::string>();

        return true;
    }

    static bool ProcessResource()
    {
        char tm[16];
        json data = json::parse(m_pData);

        auto result = data["response"]["result"].get<int>();
        if (result != 1)
        {
            printf("Web api return failure code %d\n", result);
            return false;
        }

        //Record time in the response
        time_t now = time(nullptr);
        snprintf(tm, sizeof(tm), "%lli", now);
        data[CM_FILE_TIME_FEILD] = tm;

        if (!PickCMServerFromJson(data))
            return false;

        //Write cache to file
        {
            std::lock_guard<std::mutex> lock(m_CMListLock);
            std::string dump = data.dump();
            std::ofstream out(CM_FILE_NAME, std::ofstream::out | std::ofstream::binary);
            out.write(dump.c_str(), dump.size());
            out.close();
        }

        return true;
    }

    static size_t CurlWriteDataCallback(void* ptr, size_t size, size_t nmemb, void* stream)
    {
        if (m_pData)
            delete[] m_pData;

        m_DataLength = size * nmemb;
        m_pData = new char[m_DataLength + 1];
        memcpy(m_pData, ptr, m_DataLength);
        m_pData[m_DataLength] = 0;

        return m_DataLength;
    }

private:
    static char*        m_pData;
    static size_t       m_DataLength;
    static std::string  m_CMAddr;
    static std::mutex   m_CMListLock;
};

inline char*        SteamWebApiHelper::m_pData = nullptr;
inline size_t       SteamWebApiHelper::m_DataLength = 0;
inline std::string  SteamWebApiHelper::m_CMAddr;
inline std::mutex   SteamWebApiHelper::m_CMListLock;

#endif // !__TINY_STEAM_CLIENT_WEBAPIHELPER_HPP__
