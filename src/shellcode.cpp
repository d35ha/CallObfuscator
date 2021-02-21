/*!     @file
 *
 *    This file contains the functionality
 *    of building the shellcode.
 *
 */

#ifndef SHELLCODE_CPP
#define SHELLCODE_CPP

 // The includes.
#include <shellcode.hpp>
#include <winternl.h>

// Needed variables.
PVOID shellcode::shellcode_start = exit;
DWORD shellcode::shellcode_entry = (DWORD)((PBYTE)load_syms - (PBYTE)shellcode_start);
DWORD shellcode::shellcode_size = (DWORD)((PBYTE)funs_end - (PBYTE)shellcode_start);

// Table holding the pointers and the sizes of the shellcode functions.
DWORD shellcode::shellcodes_funs[] =
{
    (DWORD)((PBYTE)exit -               (PBYTE)shellcode_start),
    (DWORD)((PBYTE)wstr_len -           (PBYTE)shellcode_start),
    (DWORD)((PBYTE)hash_string -        (PBYTE)shellcode_start),
    (DWORD)((PBYTE)str_cpy -            (PBYTE)shellcode_start),
    (DWORD)((PBYTE)str_toi -            (PBYTE)shellcode_start),
    (DWORD)((PBYTE)str_chr -            (PBYTE)shellcode_start),
    (DWORD)((PBYTE)ansi_to_wide -       (PBYTE)shellcode_start),
    (DWORD)((PBYTE)wstr_cpy -           (PBYTE)shellcode_start),
    (DWORD)((PBYTE)wstr_i_cmp -         (PBYTE)shellcode_start),
    (DWORD)((PBYTE)get_dll_handle -     (PBYTE)shellcode_start),
    (DWORD)((PBYTE)load_dll -           (PBYTE)shellcode_start),
    (DWORD)((PBYTE)resolve_api_set -    (PBYTE)shellcode_start),
    (DWORD)((PBYTE)get_symbol_ptr -     (PBYTE)shellcode_start),
    (DWORD)((PBYTE)load_syms -          (PBYTE)shellcode_start)
};

// Disable the runtime checks.
#pragma runtime_checks("", off)

// Stop the execution of the shellcode.
VOID shellcode::exit() 
{
    // Just break.
    __debugbreak();
};

// Length of wide string
size_t shellcode::wstr_len(PWSTR str)
{
    PWCHAR s = (PWCHAR)str;
    for (; *s; ++s);
    return(s - str);
};

// Compile time string hashing.
DWORD shellcode::hash_string(PCHAR str)
{
    // Init value.
    DWORD hash = 0;

    // Loop on the chars.
    while (*str)
    {
        // Build it.
        hash += *str++;
        hash += hash << 10;
        hash ^= hash >> 6;
    };

    // Finish.
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
};

// Copy string to a buffer.
VOID shellcode::str_cpy(PCHAR out, PSTR in)
{
    while (*in) *out++ = *in++;
    *out = 0;
};

// Convert a string into integer.
DWORD shellcode::str_toi(PSTR str)
{
    // Init.
    DWORD result = 0;
    BYTE digit;

    // Convert.
    for (; ; str += 1) {
        digit = *str - '0';
        if (digit > 9)
            break;
        result = (10 * result) + digit;
    };

    // Return.
    return result;
};

// Search for a char inside a string.
PCHAR shellcode::str_chr(PSTR str, CHAR chr)
{
    // Search for it.
    do {
        if (*str == chr) { return str; };
    } while (*str++);
    return (0);
};

// Convert ansi to wide chars.
VOID shellcode::ansi_to_wide(PCHAR str, PWCHAR out, size_t size)
{
    // Test if the buffer is zero-length.
    size /= sizeof(WCHAR);
    if (!size) return;

    // Copy the chars.
    while (--size && *str) {
        *out++ = (WCHAR)*str++;
    };

    // Append NULL.
    *out = 0;
};

// Copy string between to buffers.
VOID shellcode::wstr_cpy(PWSTR str1, PCWSTR str2, size_t length)
{
    // Char by char.
    while (length--) *str1++ = *str2++;
    *str1 = 0;
};


// Compare two wide strings.
INT shellcode::wstr_i_cmp(PWSTR str1, PCWSTR str2, size_t length)
{
    // Init.
    WCHAR c1, c2;
    do
    {
        // Make the check.
        c1 = *str1++;
        c2 = *str2++;
        if (c1 == L'\0') {
            return c2 - c1;
        };

        // Move to the next iteration.
    } while (((c1 == c2) || (c1 - c2 == 32) ||
        (c2 - c1 == 32)) && --length);

    // Final compare.
    return c2 - c1;
};

// Get the dll base by name.
HANDLE shellcode::get_dll_handle(HANDLE pe_base, PDWORD sh_funs, PWSTR dll_name)
{
    // Resolving the needed functions.
    auto fun_wstr_i_cmp = sh_resolve(pe_base, sh_funs, wstr_i_cmp);
    auto fun_resolve_api_set = sh_resolve(pe_base, sh_funs, resolve_api_set);

    // Needed local variables.
    PPEB pPeb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;

QUERY_LDR:

    // Looping on the LDR modules (ordered as in memory).
    PLIST_ENTRY current = head;
    while ((current = current->Flink) != head)
    {
        // Get and test the current module.
        PLDR_DATA_TABLE_ENTRY data_table = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // If the current module is the needed one.
        if (!fun_wstr_i_cmp(((PUNICODE_STRING)(&data_table->Reserved4))->Buffer,
            dll_name, 0))
        {
            // Return the module base.
            return data_table->DllBase;
        };
    };

    // Check if api set schema.
    WCHAR api_schema[] = { L'a', L'p', L'i', L'-', L'\0' };
    WCHAR ext_schema[] = { L'e', L'x', L't', L'-', L'\0' };
    if (!fun_wstr_i_cmp(dll_name, api_schema, sizeof("api")) ||
        !fun_wstr_i_cmp(dll_name, ext_schema, sizeof("ext")))
    {
        // The length of the dll name is more than the api set dll name.
        if (fun_resolve_api_set(pe_base, sh_funs, pPeb->Reserved9[0], dll_name, dll_name)) {
            goto QUERY_LDR;
        };
    };

    // Not found.
    return NULL;
};

// Load the dll base by name.
HANDLE shellcode::load_dll(HANDLE pe_base, PDWORD sh_funs, PCHAR dll_name)
{
    // Resolving the needed functions.
    auto fun_ansi_to_wide = sh_resolve(pe_base, sh_funs, ansi_to_wide);
    auto fun_get_dll_handle = sh_resolve(pe_base, sh_funs, get_dll_handle);
    auto fun_get_symbol_ptr = sh_resolve(pe_base, sh_funs, get_symbol_ptr);
    auto fun_wstr_len = sh_resolve(pe_base, sh_funs, wstr_len);
    auto fun_hash_string = sh_resolve(pe_base, sh_funs, hash_string);

    // Converting the dll name.
    WCHAR dll_buffer[MAX_PATH];
    fun_ansi_to_wide(dll_name, dll_buffer, sizeof(dll_buffer));

    // Quering the ldr first.
    HANDLE h_dll = fun_get_dll_handle(pe_base, sh_funs, dll_buffer);
    if (h_dll) return h_dll;

    // Getting the base of the ntdll.
    WCHAR ntdll_name[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    HANDLE h_ntdll = fun_get_dll_handle(pe_base, sh_funs, ntdll_name);
    if (!h_ntdll) return NULL;

    // Resolving `LdrLoadDll` to load the new dll.
    u_sym_info ldr_load_dll_info;
    CHAR ldrloaddll_name[] = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', '\0' };
    ldr_load_dll_info.sym_hash = fun_hash_string(ldrloaddll_name);
    pLdrLoadDll fLdrLoadDll = (pLdrLoadDll)fun_get_symbol_ptr(pe_base, sh_funs, h_ntdll, ldr_load_dll_info, TRUE);
    if (fLdrLoadDll == NULL) {
        return NULL;
    };

    // Loading the required dll using `LdrLoadDll`.
    UNICODE_STRING u_module = {
        (USHORT)(fun_wstr_len(dll_buffer) * 2),
        (USHORT)(fun_wstr_len(dll_buffer) * 2 + 2),
        (PWCHAR)dll_buffer
    };

    // Loading the dll.
    if (!NT_SUCCESS(fLdrLoadDll(
        NULL, 0,
        &u_module,
        &h_dll
    ))) return NULL;

    // Return the loaded module base.
    return h_dll;
};

// Resolve the api set schema for the dll name.
BOOL shellcode::resolve_api_set(HANDLE pe_base, PDWORD sh_funs, PVOID schema_map, PCWSTR virtual_dll, PWCHAR real_dll)
{
    // Resolving the needed functions.
    auto fun_wstr_cpy = sh_resolve(pe_base, sh_funs, wstr_cpy);
    auto fun_wstr_i_cmp = sh_resolve(pe_base, sh_funs, wstr_i_cmp);

    // Reading the version.
    DWORD Version = *(DWORD*)schema_map;

    // Two versions with two methods.
    if (Version >= 3) {

        // Use the proper structures.
        PApiSetHeader63 pHeader = (PApiSetHeader63)schema_map;
        PApisetNameEntry pApiSets = (PApisetNameEntry)((PBYTE)schema_map + pHeader->NamesOffset);

        // Use binary search to enumerate the dlls.
        INT Start, End, Next, CmpResult;
        Start = Next = 0;
        End = (DWORD)pHeader->NumberOfApisets - 1;

        // Binary search loop.
        while (End >= Start) {

            Next = (Start + End) >> 1;
            PWCHAR VirtualDll = (PWCHAR)((PBYTE)schema_map + pApiSets[Next].Offset);

            // Compare and conditions.
            CmpResult = fun_wstr_i_cmp(VirtualDll, virtual_dll, pApiSets[Next].Size / 2);
            if (CmpResult < 0)
                End = Next - 1;
            else if (CmpResult > 0)
                Start = Next + 1;
            else break;
        };

        // We've found the right entry.
        if (End >= Start && pApiSets[Next].NumberOfHosts) {

            // Get the value.
            PApisetValueEntry pValue = (PApisetValueEntry)((PBYTE)schema_map + pApiSets[Next].HostOffset);
            pValue += pApiSets[Next].NumberOfHosts - 1;

            // Fill the buffer address and return true.
            fun_wstr_cpy(real_dll, (PWCHAR)((PBYTE)schema_map + pValue->ValueOffset),
                pValue->ValueLength / 2);
            return TRUE;
        };
    }
    else {

        // Use the proper structures.
        PApiSetHeader6 pHeader = (PApiSetHeader6)schema_map;
        PApisetNameEntry2 pApiSets = (PApisetNameEntry2)((PBYTE)schema_map + sizeof(ApiSetHeader6));

        // Use binary search to enumerate the dlls.
        int Start, End, Next, CmpResult;
        Start = Next = 0;
        End = (DWORD)pHeader->Count - 1;

        // Binary search loop.
        while (End >= Start) {

            Next = (Start + End) >> 1;
            PWCHAR VirtualDll = (PWCHAR)((PBYTE)schema_map + pApiSets[Next].NameOffset);

            // Compare and conditions.
            CmpResult = fun_wstr_i_cmp(VirtualDll, virtual_dll, pApiSets[Next].NameLength / 2);
            if (CmpResult < 0)
                End = Next - 1;
            else if (CmpResult > 0)
                Start = Next + 1;
            else break;
        };

        // We've found the right entry and if there are any availible values.
        DWORD ValuesCount;
        if (End >= Start && (ValuesCount = *(DWORD*)((PBYTE)schema_map + pApiSets[Next].DataOffset))) {

            // Get the value.
            PValuesEntry2 pValue = (PValuesEntry2)((PBYTE)schema_map + pApiSets[Next].DataOffset);
            pValue += ValuesCount - 1;

            // Fill the buffer address and return True.
            fun_wstr_cpy(real_dll, (PWCHAR)((PBYTE)schema_map + pValue->ValueOffset),
                pValue->ValueLength / 2);
            return TRUE;
        };
    };

    // Not found.
    return FALSE;
};

// Get the dll base by name.
PVOID shellcode::get_symbol_ptr(HANDLE pe_base, PDWORD sh_funs, HANDLE dll_handle, u_sym_info sym_info, BOOL by_name)
{
    // Resolving the needed functions.
    auto fun_hash_string = sh_resolve(pe_base, sh_funs, hash_string);
    auto fun_str_cpy = sh_resolve(pe_base, sh_funs, str_cpy);
    auto fun_str_chr = sh_resolve(pe_base, sh_funs, str_chr);
    auto fun_load_dll = sh_resolve(pe_base, sh_funs, load_dll);
    auto fun_get_symbol_ptr = sh_resolve(pe_base, sh_funs, get_symbol_ptr);
    auto fun_str_toi = sh_resolve(pe_base, sh_funs, str_toi);

    // Dereferencing the headers.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)dll_handle;
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)((PBYTE)dll_handle + dos_hdr->e_lfanew);
    PIMAGE_OPTIONAL_HEADER opt_hdr = &nt_hdrs->OptionalHeader;

    // Dereferencing the export table data directory.
    PIMAGE_DATA_DIRECTORY data_dir = &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // Check if exists.
    if (!data_dir->VirtualAddress || !data_dir->Size) {
        return NULL;
    };

    // Get the export table pointer.
    PIMAGE_EXPORT_DIRECTORY export_table = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dll_handle +
        data_dir->VirtualAddress);

    // In case an ordinal is resolved.
    DWORD f_address;
    if (!by_name)
    {
        // Invalid ordinal.
        if (sym_info.sym_ord < export_table->Base ||
            sym_info.sym_ord >= export_table->Base + export_table->NumberOfFunctions)
            return NULL;

        // Getting the address directly.
        f_address = ((DWORD*)((PBYTE)dll_handle + export_table->AddressOfFunctions))
            [sym_info.sym_ord - export_table->Base];
    }
    else
    {
        // My be no names exported.
        if (!export_table->AddressOfNames) {
            return NULL;
        };

        // Resolve by name.
        size_t idx = 0;
        DWORD* p_names = (DWORD*)((PBYTE)dll_handle +
            export_table->AddressOfNames);
        for (; idx < export_table->NumberOfNames; idx++)
        {
            // Get the name.
            PCHAR sym_name = (PCHAR)dll_handle + p_names[idx];
            if (fun_hash_string(sym_name) != sym_info.sym_hash)
                continue;

            // Found.
            f_address = ((DWORD*)((PBYTE)dll_handle + export_table->AddressOfFunctions))[
                ((PWORD)((PBYTE)dll_handle + export_table->AddressOfNameOrdinals))[idx]
            ];
            break;
        };

        // Test if not found.
        if (idx == export_table->NumberOfNames)
        {
            // Not found.
            return NULL;
        };
    };

    // Test if the symbol is forwarded.
    PVOID p_address = (PBYTE)dll_handle + f_address;
    if (f_address >= data_dir->VirtualAddress &&
        f_address < data_dir->VirtualAddress + data_dir->Size)
    {
        // Reading the dll name and the function name.
        CHAR dll_name[MAX_PATH], sym_name[MAX_PATH];
        fun_str_cpy(dll_name, (PCHAR)p_address);

        // Appending ".dll".
        PCHAR dot_loc = fun_str_chr(dll_name, '.');
        fun_str_cpy(sym_name, ++dot_loc);
        *dot_loc++ = 'd';
        *dot_loc++ = 'l';
        *dot_loc++ = 'l';
        *dot_loc++ = '\0';

        // Load the dll.
        HANDLE h_forward = fun_load_dll(pe_base, sh_funs, dll_name);
        if (!h_forward) return NULL;

        // Re make the resolve.
        u_sym_info sym_data;
        if (*sym_name == '#') {
            // By ordinal.
            sym_data.sym_ord = (WORD)fun_str_toi(&sym_name[1]);
            p_address = fun_get_symbol_ptr(pe_base, sh_funs, h_forward, sym_data, FALSE);
        }
        else
        {
            // By name.
            sym_data.sym_hash = fun_hash_string(sym_name);
            p_address = fun_get_symbol_ptr(pe_base, sh_funs, h_forward, sym_data, TRUE);
        };
    };

    // Resolved.
    return p_address;
};

// Load the obfuscated symbols at runtime.
VOID shellcode::load_syms(HANDLE pe_base, DWORD sh_funs_rva, DWORD syms_rva)
{
    // Calculate the pointers.
    PDWORD sh_funs = (PDWORD)((PBYTE)pe_base + sh_funs_rva);
    p_obfuscated_sym syms = (p_obfuscated_sym)((PBYTE)pe_base + syms_rva);

    // Resolving the needed functions.
    auto fun_load_dll = sh_resolve(pe_base, sh_funs, load_dll);
    auto fun_get_symbol_ptr = sh_resolve(pe_base, sh_funs, get_symbol_ptr);
    auto fun_load_halt = sh_resolve(pe_base, sh_funs, exit);
    
    // Looping on the entries.
    while (syms->dll_name)
    {
        // Calculate the pointers.
        p_obfuscated_sym p_sym = syms++;
        PCHAR c_dll_name = (PCHAR)pe_base + p_sym->dll_name;
        PVOID* p_thunk = (PVOID*)((PBYTE)pe_base + p_sym->sym_thnk);

        // Get the loaded dll handle.
        HANDLE dll_handle = fun_load_dll(pe_base, sh_funs, c_dll_name);
        if (!dll_handle)
        {
            // The dll is not loaded.
            return fun_load_halt();
        };

        // Get the symbol address.
        PVOID sym_ptr = fun_get_symbol_ptr(pe_base, sh_funs, dll_handle, p_sym->sym_info, p_sym->by_name);
        if (!dll_handle)
        {
            // The symbol is not found.
            return fun_load_halt();
        };

        // Replace the symbol thunk.
        *p_thunk = sym_ptr;
    };
};

// Used to flag the end of the functions.
VOID shellcode::funs_end() {};

// Renable the runtime checks.
#pragma runtime_checks("", restore)

#endif // !SHELLCODE_CPP.