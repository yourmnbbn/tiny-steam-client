#include <cstdio>
#include "argparser.hpp"
#include "SteamClient.hpp"
#include "WebApiHelper.hpp"
#include "json/json.hpp"

int main(int argc, char** argv)
{
    InitializeCryptoTool();
	
    ArgParser parser;

    parser.AddOption("-user", "Steam account username.", OptionAttr::OptionalWithValue, OptionValueType::STRING);
    parser.AddOption("-pw", "Steam account password.", OptionAttr::OptionalWithValue, OptionValueType::STRING);
    parser.AddOption("-tfc", "Steam two factor code.(Received by steam mobile)", OptionAttr::OptionalWithValue, OptionValueType::STRING);
    parser.AddOption("-ac", "Steam auth code.(Received by email)", OptionAttr::OptionalWithValue, OptionValueType::STRING);

    parser.AddOption("-sip", "Tiny csgo server ip.", OptionAttr::OptionalWithValue, OptionValueType::STRING);
    parser.AddOption("-sport", "Tiny csgo server ip.", OptionAttr::OptionalWithValue, OptionValueType::INT16U);
    parser.AddOption("-acfile", "Accounts file path.", OptionAttr::OptionalWithValue, OptionValueType::STRING);

    //Parse arguments
    try
    {
        parser.ParseArgument(argc, argv);
    }
    catch (const std::exception& e)
    {
        printf("%s\n", e.what());
        return -1;
    }
    
    //Check argumtents
    if (parser.OptionCount() < 1)
    {
        parser.PrintOptions();
        return -1;
    }

    SteamClientMgr clientmgr;
    json data;

    if (parser.HasOption("-acfile"))
    {
        try
        {
            //Read accounts from a json file
            std::ifstream file(parser.GetOptionValueString("-acfile"), std::ifstream::in);
            file >> data;

            for (const auto& [key, value] : data["accounts"].items())
            {
                std::string user = value["user"];
                std::string passwd = value["passwd"];

                printf("Read account %s, password %s\n", user.c_str(), passwd.c_str());
                clientmgr.AddAccount(user.c_str(), passwd.c_str());
            }
        }
        catch (const std::exception& e)
        {
            printf("Process account file failed! %s\n", e.what());
            return -1;
        }
    }
    else
    {
        if (!(parser.HasOption("-user") && parser.HasOption("-pw")))
        {
            printf("If you don't provide a account file, you must provide account username and password.\n");
            return -1;
        }

        clientmgr.AddAccount(parser.GetOptionValueString("-user"),
            parser.GetOptionValueString("-pw"),
            parser.GetOptionValueString("-tfc"),
            parser.GetOptionValueString("-ac")
        );
    }

    //If provided both, will cause a login error
    if (parser.HasOption("-tfc") && parser.HasOption("-ac"))
    {
        printf("Detected both -tfc and -ac provided, you can only provide one of them!\n");
        return -1;
    }

    if (parser.HasOption("-sip") && parser.HasOption("-sport"))
    {
        printf("Starting authentication thread\n");
        //We authenticate user in a seperate thread
        std::thread(
            [&parser]()-> void
            {
                AuthClient aclient(parser);
                aclient.RunClient();
            }
        ).detach();
    }
    
    //Run each client
    clientmgr.RunClients();
    return 0;
}
