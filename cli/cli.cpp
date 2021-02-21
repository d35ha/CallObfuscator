
/*!     @file
 *
 *      This file contains the cli main functionality.
 */

// Includes.
#include "ini.h"
#include <iostream>
#include <cobf.hpp>

// Processed line handler.
void ini_line_handler(void* data, unsigned int line, const char* sec, const char* nam, const char* val)
{
    // Cast the needed pointer.
    cobf* p_obf_file = (cobf*)data;
    cobf_error ret_err;
    char error[MAX_PATH];

    // Saving the old section.
    static string s_sec = "";
    if (sec) 
    {
        // Get the dll name.
        s_sec = sec;
        return;
    };

    // Name/ordinals checking.
    if (*nam != '#' && *val != '#') ret_err = p_obf_file->obf_sym(s_sec.c_str(), nam, val);
    else if (*nam != '#' && *val == '#') ret_err = p_obf_file->obf_sym(s_sec.c_str(), nam, atoi(val + 1));
    else if (*nam == '#' && *val != '#') ret_err = p_obf_file->obf_sym(s_sec.c_str(), atoi(nam + 1), val);
    else ret_err = p_obf_file->obf_sym(s_sec.c_str(), atoi(nam + 1), atoi(val + 1));

    // Check the error.
    if (ret_err != cobf_error::COBF_NO_ERROR)
    {
        // Error at processing.
        cobf_format_message(ret_err, error, sizeof(error));
        cout << "[-] Error at the config at line " << line << ": " << error << endl;
    };
};

// The main entry.
int main(int argc, char** argv)
{
    // Expecting the input file, out file and the config file.
    if (argc < 3 || argc > 4)
    {
        // Print help.
        cout << *argv << " <input file> <out file> [config file]" << endl;
        return 1;
    };

    // Getting the data.
    char* input_file = argv[1];
    char* out_file = argv[2];
    char* config_file = argc == 4 ? argv[3] : (char*)"config.ini";

    // Needed locals.
    cobf_error ret_err;
    char error[MAX_PATH];
    try
    {
        // Loading the input file.
        cobf obf_file = cobf(input_file);
        if ((ret_err = obf_file.load_pe()) != cobf_error::COBF_NO_ERROR)
        {
            // Error at loading.
            cobf_format_message(ret_err, error, sizeof(error));
            cout << "[-] Error at loading the file: " << error << endl;
            return 1;
        };

        // Log.
        cout << "[+] File loaded successfully." << endl;

        // Process the config file.
        if (!parse_ini_file(config_file, ini_line_handler, &obf_file))
        {
            // Error at processing the config.
            cout << "[-] Error occurred while processing the config file." << endl;
            return 1;
        };

        // Obfuscating it.
        if ((ret_err = obf_file.generate(out_file)) != cobf_error::COBF_NO_ERROR)
        {
            // Error at obfuscating.
            cobf_format_message(ret_err, error, sizeof(error));
            cout << "[-] Error at obfuscating the file: " << error << endl;
            return 1;
        };

        // Log.
        cout << "[+] File obfuscated successfully." << endl;

        // Unloading it.
        if ((ret_err = obf_file.unload_pe()) != cobf_error::COBF_NO_ERROR)
        {
            // Error at unloading.
            cobf_format_message(ret_err, error, sizeof(error));
            cout << "[-] Error at unloading the file: " << error << endl;
            return 1;
        };

        // Log.
        cout << "[+] File unloaded successfully." << endl;

    }
    catch (...)
    {
        // Log.
        cout << "[!] Unhandled exception occurred." << endl;
        return 1;
    };

    // Done.
    return 0;
};