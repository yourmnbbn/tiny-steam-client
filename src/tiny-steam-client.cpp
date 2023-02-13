#include <cstdio>
#include "argparser.hpp"
#include "SteamClient.hpp"

int main(int argc, char** argv)
{
    InitializeCryptoTool();
	
    ArgParser parser;

    parser.AddOption("-cm", "CM Server socket e.g. 127.0.0.1:27017", OptionAttr::RequiredWithValue, OptionValueType::STRING);
    parser.AddOption("-user", "Steam account username.", OptionAttr::RequiredWithValue, OptionValueType::STRING);
    parser.AddOption("-pw", "Steam account password.", OptionAttr::RequiredWithValue, OptionValueType::STRING);

    try
    {
        parser.ParseArgument(argc, argv);
    }
    catch (const std::exception& e)
    {
        printf("%s\n", e.what());
        return -1;
    }
    
    SteamClient sclient(parser);
    sclient.SetCMServer(parser.GetOptionValueString("-cm"));
    sclient.SetAccount(parser.GetOptionValueString("-user"), parser.GetOptionValueString("-pw"));
    sclient.RunClient();
}
