
/*!     @file
 *
 *    This file contains the main functionality
 *    of the ini parser.
 *
 */

#ifndef INI_C
#define INI_C

// Includes.
#include "ini.h"
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Parse the file and return line by line.
    int parse_ini_file(const char* f_path, ini_line_cb handler, void* data)
    {
        // Open the file stream.
        FILE* h_file;
        if (fopen_s(&h_file, f_path, "r") || !h_file) return 0;

        // Current line.
        char* c_str_ptr = 0, * c_str_ptr_end = 0;
        char c_line[MAX_INI_LINE];

        // Read it in a loop for each line.
        unsigned int line_number = 1;
        while (fgets(c_line, sizeof(c_line), h_file))
        {
            // Comment.
            if (*c_line == ';') {
                line_number++;
                continue;
            };

            // It may be a section.
            if (*c_line == '[' && (c_str_ptr = strchr(c_line, ']')))
            {
                // New section.
                *c_str_ptr = '\0';
                handler(data, line_number, c_line + 1, 0, 0);
            }
            else if ((c_str_ptr = strchr(c_line, '=')))
            {
                // It may be a name[=]value.
                if ((c_str_ptr_end = strchr(c_str_ptr, '\n'))) {
                    *c_str_ptr_end = '\0';
                };

                // Call the handler with name-value pair.
                *c_str_ptr = '\0';
                handler(data, line_number, 0, c_line, c_str_ptr + 1);
            }
            else
            {
                // Close the file and return FALSE.
                fclose(h_file);
                return 0;
            };

            // Next.
            line_number++;
        };

        // Close the file.
        fclose(h_file);
        return 1;
    };

#ifdef __cplusplus
};
#endif
#endif // !INI_C.