
/*!     @file
 *
 *      This file contains the utilities
 *      used by the library.
 */


#ifndef SHELLCODE_HPP
#define SHELLCODE_HPP

// The includes.
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

// No inline macros.
#ifdef _MSC_VER
#define no_inline __declspec(noinline)
#else
#define no_inline __attribute__((noinline))
#endif

// Resolving a function internally.
#define sh_resolve(base, funs, fun) (decltype(fun)*)((PBYTE)base + \
    funs[shellcode_fun_##fun])

// Utility class represents the shellcode builder.
class shellcode
{
    // To access the internals.
    friend class cobf;
private:

    // Union of the symbol hash and ordinal.
    typedef union {
        DWORD   sym_hash;   /*!< The symbol hash used to query it. */
        WORD    sym_ord;    /*!< The symbol ordinal used to query it. */
    } u_sym_info;

    // Struct of an obfuscated API.
    typedef struct {
        DWORD       dll_name;   /*!< Offset to the dll name. */
        BOOL        by_name;    /*!< True if the symbol is imported by name. */
        u_sym_info  sym_info;   /*!< The information . */
        DWORD       sym_thnk;   /*!< Offset to the first thunk that represents the symbol. */
    } obfuscated_sym, * p_obfuscated_sym;

    // Api set schema version 3.
    typedef struct _ApiSetHeader63 {
        DWORD Version;          /*!< The version of the api set schema (6,3). */
        DWORD Size;             /*!< Size of the whole table. */
        DWORD Sealed;           /*!< Unknown (undocumented). */
        DWORD NumberOfApisets;  /*!< Number of entries at the table. */
        DWORD NamesOffset;      /*!< Offset to the names table. */
        DWORD TableOffset;      /*!< Unknown (undocumented). */
        DWORD Multiplier;       /*!< Unknown (undocumented). */
    } ApiSetHeader63, * PApiSetHeader63;

    // Api set schema name entry.
    typedef struct _ApisetNameEntry {
        DWORD Sealed;           /*!< Unknown (undocumented). */
        DWORD Offset;           /*!< Offset to the virtual dll name. */
        DWORD Ignored;          /*!< Unknown (undocumented). */
        DWORD Size;             /*!< Size of the virtual dll name. */
        DWORD HostOffset;       /*!< Offset to the real dll name. */
        DWORD NumberOfHosts;    /*!< Number of resolved dlls. */
    } ApisetNameEntry, * PApisetNameEntry;

    // Api set schema value entry.
    typedef struct _ApisetValueEntry {
        DWORD Ignored;          /*!< Unknown (undocumented). */
        DWORD NameOffset;       /*!< Offset to the name. */
        DWORD NameLength;       /*!< Length of the name. */
        DWORD ValueOffset;      /*!< Offset to the value. */
        DWORD ValueLength;      /*!< Loength of the value. */
    } ApisetValueEntry, * PApisetValueEntry;

    // Api set schema version 6.
    typedef struct _ApiSetHeader6 {
        DWORD Version;          /*!< Version of the api set schema. */
        DWORD Count;            /*!< Number of entries. */
    } ApiSetHeader6, * PApiSetHeader6;

    // Api set schema another version name entry.
    typedef struct _ApisetNameEntry2 {
        DWORD NameOffset;       /*!< Offset to the name. */
        DWORD NameLength;       /*!< Length of the name. */
        DWORD DataOffset;       /*!< Offset to the values. */
    } ApisetNameEntry2, * PApisetNameEntry2;

    // Api set schema another version value entry.
    typedef struct _ValuesArray2 {
        DWORD Count;            /*!< Number of values. */
        DWORD NameLength;       /*!< Length of name. */
        DWORD DataOffset;       /*!< Offset to the values. */
    } ValuesArray2, * PValuesArray2;

    // Api set schema another version values entry.
    typedef struct _ValuesEntry2 {
        DWORD NameOffset;       /*!< Offset to the name. */
        DWORD NameLength;       /*!< Length of the name. */
        DWORD ValueOffset;      /*!< Offset to the value. */
        DWORD ValueLength;      /*!< Loength of the value. */
    } ValuesEntry2, * PValuesEntry2;

    // For LdrLoadDll.
    typedef NTSTATUS (WINAPI* pLdrLoadDll)(
        PCWSTR              PathToFile,     /*!< Dll file path. */
        DWORD               Flags,          /*!< Loading flags. */
        PUNICODE_STRING     ModuleFileName, /*!< File name directly. */
        PVOID*              ModuleHandle);  /*!< Receives the handle. */

    /*!     @ingroup        SHELLCODE
     *      @brief          Stop the execution of the shellcode.
     */
    static no_inline VOID exit();

    /*!     @ingroup        SHELLCODE
     *      @brief          Calculate the length of wide string.
     *      @param[in]      str String to calculate length to.
     *      @return         The calculated length.
     */
    static no_inline size_t wstr_len(PWSTR str);

    /*!     @ingroup        SHELLCODE
     *      @brief          Calculate a hash of a string.
     *      @param[in]      str String to calculate hash to.
     *      @return         The calculated hash.
     */
    static no_inline DWORD hash_string(PCHAR str);

    /*!     @ingroup        SHELLCODE
     *      @brief          Copy string to a buffer.
     *      @param[in]      out Buffer to receive the string.
     *      @param[in]      in String to copy.
     */
    static no_inline VOID str_cpy(PCHAR out, PSTR in);

    /*!     @ingroup        SHELLCODE
     *      @brief          Convert a string into integer.
     *      @param[in]      str String to convert.
     *      @return         The integer value.
     */
    static no_inline DWORD str_toi(PSTR str);

    /*!     @ingroup        SHELLCODE
     *      @brief          Search for a char inside a string.
     *      @param[in]      str String to search in.
     *      @param[in]      chr Char to search for.
     *      @return         Location of the char.
     */
    static no_inline PCHAR str_chr(PSTR str, CHAR chr);

    /*!     @ingroup        SHELLCODE
     *      @brief          Convert ansi to wide chars.
     *      @param[in]      str String to convert.
     *      @param[out]     out Wide string to receive the wide string.
     *      @param[in]      size Size of the out buffer.
     */
    static no_inline VOID ansi_to_wide(PCHAR str, PWCHAR out, size_t size);

    /*!     @ingroup        SHELLCODE
     *      @brief          Copy string between to buffers.
     *      @param[out]     str1 Receives the copied string.
     *      @param[in]      str2 Wide string to copy.
     *      @param[in]      length Length of the string to copy.
     */
    static no_inline VOID wstr_cpy(PWSTR str1, PCWSTR str2, size_t length);

    /*!     @ingroup        SHELLCODE
     *      @brief          Compare two wide strings.
     *      @param[in]      str String to convert.
     *      @param[in]      out Wide string to receive the wide string.
     *      @param[in]      length The length of chars to compare (if 0, it will be ignored).
     *      @return         Difference between the last two chars.
     */
    static no_inline INT wstr_i_cmp(PWSTR str1, PCWSTR str2, size_t length);

    /*!     @ingroup        SHELLCODE
     *      @brief          Get the dll base by name.
     *      @param[in]      dll_name The dll name.
     *      @return         The base of the dll if found or NULL.
     */
    static no_inline HANDLE get_dll_handle(HANDLE pe_base, PDWORD sh_funs, PWSTR dll_name);

    /*!     @ingroup        SHELLCODE
     *      @brief          Load the dll base by name.
     *      @param[in]      dll_name The dll name.
     *      @return         The base of the dll if found or NULL.
     */
    static no_inline HANDLE load_dll(HANDLE pe_base, PDWORD sh_funs, PCHAR dll_name);

    /*!     @ingroup        SHELLCODE
     *      @brief          Resolve the api set schema for the dll name.
     *      @param[in]      schema_map Pointer to the api set schema map.
     *      @param[in]      virtual_dll The dll to convert.
     *      @param[out]     real_dll Receives the dll name.
     *      @return         True if succeeded, false if not.
     */
    static no_inline BOOL resolve_api_set(HANDLE pe_base, PDWORD sh_funs, PVOID schema_map,
        PCWSTR virtual_dll, PWCHAR real_dll);

    /*!     @ingroup        SHELLCODE
     *      @brief          Get the dll base by name.
     *      @param[in]      dll_handle The handle of the dll to be queried.
     *      @param[in]      sym_info Hash or ordinal of the symbol.
     *      @param[in]      by_name True if imported by name.
     *      @return         The address of the symbol if found or NULL.
     */
    static no_inline PVOID get_symbol_ptr(HANDLE pe_base, PDWORD sh_funs, HANDLE dll_handle,
        u_sym_info sym_info, BOOL by_name);

    /*!     @ingroup        SHELLCODE
     *      @brief          Load the obfuscated symbols at runtime.
     *      @param[in]      pe_base The base of the current executable at memory.
     *      @param[in]      sh_funs_rva Rva of the needed functions.
     *      @param[in]      syms_rva Rva of the table of the obfuscated symbols.
     */
    static no_inline VOID WINAPI load_syms(HANDLE pe_base, DWORD sh_funs_rva, DWORD syms_rva);

    /*!     @ingroup        SHELLCODE
     *      @brief          Used to flag the end of the functions.
     */
    static no_inline VOID funs_end();

    // Enum of the functions used at the shellcode.
    typedef enum {
        shellcode_fun_exit = 0,         /*!< Identifier for shellcode::exit. */
        shellcode_fun_wstr_len,         /*!< Identifier for shellcode::wstr_len. */
        shellcode_fun_hash_string,      /*!< Identifier for shellcode::hash_string. */
        shellcode_fun_str_cpy,          /*!< Identifier for shellcode::str_cpy. */
        shellcode_fun_str_toi,          /*!< Identifier for shellcode::str_toi. */
        shellcode_fun_str_chr,          /*!< Identifier for shellcode::str_chr. */
        shellcode_fun_ansi_to_wide,     /*!< Identifier for shellcode::ansi_to_wide. */
        shellcode_fun_wstr_cpy,         /*!< Identifier for shellcode::wstr_cpy. */
        shellcode_fun_wstr_i_cmp,       /*!< Identifier for shellcode::wstr_i_cmp. */
        shellcode_fun_get_dll_handle,   /*!< Identifier for shellcode::get_dll_handle. */
        shellcode_fun_load_dll,         /*!< Identifier for shellcode::load_dll. */
        shellcode_fun_resolve_api_set,  /*!< Identifier for shellcode::resolve_api_set. */
        shellcode_fun_get_symbol_ptr,   /*!< Identifier for shellcode::get_symbol_ptr. */
        shellcode_fun_load_syms,        /*!< Identifier for shellcode::load_syms. */
        shellcode_number_of_functions   /*!< Number of the shellcode functions. */
    } t_shellcode_funs;

public:

    static PVOID shellcode_start;   /*!< Start of the raw shellcode to be copied. */
    static DWORD shellcode_entry;   /*!< Offset from the start for the entry of the shellcode. */
    static DWORD shellcode_size;    /*!< Size of the shellcode. */

    /*!< Table holding the offsets of the shellcode functions. */
    static DWORD shellcodes_funs[shellcode_number_of_functions];
};

#endif // !SHELLCODE_HPP.