# tiny-steam-client
 A replacement of steam_api for [tiny-csgo-client](https://github.com/yourmnbbn/tiny-csgo-client) and [tiny-csgo-server](https://github.com/yourmnbbn/tiny-csgo-server).   

 Currently it's a demo. But it can do some useful things already.

 ### What can it do now
 - Automatically request steam CM server list.
 - Establish connection with steam CM servers. 
 - Logon lots of your steam accounts in a single process. 
 - Generating appication auth session ticket. (Can be successfully validated)
 - Communicate with GC.
 - Send ticket to tiny-csgo-server to authenticate.
 - Automatically reconnect when encounter connection error.

  In the future, tiny-steam-client will be refactored based on the current project as a replacement for steam_api to get rid of the tons of limitations brought by steam_api.  

**Note that if the steam guard of the account is activated, you have to provide secure code in the command line to be successfully logged on.**

## Dependencies
 - [hl2sdk-csgo](https://github.com/alliedmodders/hl2sdk)
 - [Asio](https://github.com/chriskohlhoff/asio) 
 - [cryptopp-8.7.0](https://github.com/weidai11/cryptopp)
 - [curl-7.87.0](https://github.com/curl/curl) (provided in source)
 - [json](https://github.com/nlohmann/json) (provided in source)
 - CMake

## Compile and Run
### Windows
1. Configure path of hl2sdk-csgo, cryptopp and Asio in `build.bat`.
2. Run `build.bat` to compile the project.
4. Run `tiny-steam-client.exe` with necessary commandline.

### Linux
1. Configure path of hl2sdk-csgo, cryptopp and Asio in `build.sh`.
2. Run `build.sh` to compile the project.
4. Run `tiny-steam-client` with necessary commandline.

 ## Command option notes
- `-user` Steam account username.
- `-pw` Steam account password.
- `-tfc` Steam two factor code. This is the code you receive in your steam mobile.
- `-ac` Steam auth code. This is the code that you receive from email.
- `-sip` Tiny csgo server ip.
- `-sport` Tiny csgo server port.
- `-acfile` Account file path.

## Example usage
1. If you want to login a single account, assuming the account name is `account`, password is `password`.
- If your account don't have steam guard protected.

```
Windows: 
tiny-steam-client.exe -user account -pw password

Linux:
./tiny-steam-client -user account -pw password
```

- If your account need a steam auth code from your email, you can use only user name and password to login once, then an auth code will be sent to your email. Assuming it's `TR3F4`.

```
Windows: 
tiny-steam-client.exe -user account -pw password -ac TR3F4

Linux:
./tiny-steam-client -user account -pw password -ac TR3F4
```

- If your account need a steam two factor code, you can directly enter the code with command line `-tfc` when it's still valid, assuming it's `Y36TG`.

```
Windows: 
tiny-steam-client.exe -user account -pw password -tfc Y36TG

Linux:
./tiny-steam-client -user account -pw password -tfc Y36TG
```

2. If you want to login multiple account, then you have to configure a accounts file in the following example json format. **Note that if you login multiple account this way, you have to make sure that the steam guard of these accounts have to be turned off! And you have to keep the program running to maintain account connection with steam CM servers all the time or the ticket will be automatically canceled by the CM if you disconnect.**

```json
{
  "accounts":{
      "1" : {
          "user"      : "account1",
          "passwd"    : "password1"
      },
      "2" : {
          "user"      : "account2",
          "passwd"    : "password2"
      },
      "3" : {
          "user"      : "account3",
          "passwd"    : "password3"
      },
      "4" : {
          "user"      : "account4",
          "passwd"    : "password4"
      },
      "..." : {
          "user"      : "...",
          "passwd"    : "..."
      }
  }
}
```

Save the file, assuming the file name is `accounts.json`. Put it where the executable is and pass the file name with option `-acfile`.

```
Windows: 
tiny-steam-client.exe -acfile accounts.json

Linux:
./tiny-steam-client -acfile accounts.json
```

3. If you want to use this to generate ticket and send them to tiny-csgo-server to authenticate, just add the `-sip` and `-sport` option. Assuming the ip is `127.0.0.1`, port is `27015`.

```
Windows: 
tiny-steam-client.exe -acfile accounts.json -sip 127.0.0.1 -sport 27015

Linux:
./tiny-steam-client -acfile accounts.json -sip 127.0.0.1 -sport 27015
```

## Credit project
 - [SteamKit](https://github.com/SteamRE/SteamKit)
 - [node-steam-user](https://github.com/DoctorMcKay/node-steam-user) 