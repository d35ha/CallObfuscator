
/*!     @file
 *
 *    This file contains the definitions
 *    of the ini parser.
 *
 */

#ifndef INI_H
#define INI_H

#define MAX_INI_LINE 0x100

#ifdef __cplusplus
extern "C" {
#endif

    /*!     @ingroup    INI
     *      @brief      Callback with the data found at each line.
     *      @param[in]  data The extra pointer to pass.
     *      @param[in]  line Processed line number.
     *      @param[in]  section Section if found.
     *      @param[in]  name Name of a normal pair.
     *      @param[in]  value Value of a normal pair.
     */
    typedef void (*ini_line_cb)(void* data, unsigned int line, const char* section,
        const char* name, const char* value);

    /*!     @ingroup    INI
     *      @brief      Parse ini file, supply the data to a callback.
     *      @param[in]  f_path The path for the ini file.
     *      @param[in]  handler The callback function.
     *      @param[in]  data Extra pointer to pass to the callback.
     *      @return     1 if done successfully, 0 if not.
     */
    int parse_ini_file(const char* f_path, ini_line_cb handler, void* data);

#ifdef __cplusplus
};
#endif
#endif // !INI_H.