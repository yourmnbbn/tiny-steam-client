# tiny-steam-client
 A replacement of steam_api for [tiny-csgo-client](https://github.com/yourmnbbn/tiny-csgo-client) and [tiny-csgo-server](https://github.com/yourmnbbn/tiny-csgo-server).   

 Currently it's a very incomplete project. It's a demo of how to establish encrypted channel with steam CM server and logon your steam account. In the future, tiny-steam-client will be designed as a replacement for steam_api to get rid of the tons of limitations brought by steam_api.  

**Note that the steam guard of the account must be turned off then the account can be logged on to steam via tiny-steam-client.**

## Dependencies
 - [hl2sdk-csgo](https://github.com/alliedmodders/hl2sdk)
 - [Asio](https://github.com/chriskohlhoff/asio) 
 - [cryptopp-8.7.0](https://github.com/weidai11/cryptopp)
 - [curl-7.87.0](https://github.com/curl/curl) (provided in source)
 - [json](https://github.com/nlohmann/json) (provided in source)
 - CMake

## Compile and Run (Currently windows only)
### Windows
1. Configure path of hl2sdk-csgo, cryptopp and Asio in `build.bat`.
2. Run `build.bat` to compile the project.
4. Run `tiny-steam-client.exe` with necessary commandline.

 ## Command option notes
- `-cm` CM server socket. (e.g. 127.0.0.1:27016) This parameter is optional, if you don't specify the server, the program will automatically load CM server from local cache or request from [web api](https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?format=json&cellid=0).
- `-user` Steam account username.
- `-pw` Steam account password.

## Credit project
 - [SteamKit](https://github.com/SteamRE/SteamKit)
 - [node-steam-user](https://github.com/DoctorMcKay/node-steam-user) 