
/*!     @file
 *
 *    This file contains the main functionality
 *    of the loader.
 *
 */

#ifndef LOAD_CPP
#define LOAD_CPP

 // The includes.
#include <cobf.hpp>
#include <time.h>

// Load the specified PE from disk.
cobf_error cobf::load_pe()
{
    // Check if already loaded.
    if (!this->pe_rawf.empty()) return cobf_error::COBF_PE_LOADED;

    // Get an access to the file.
    cobf_error ret_err = cobf_error::COBF_NO_ERROR;
    HANDLE h_file = CreateFileA(
        this->pe_path.c_str(),      // The PE file path.
        GENERIC_READ,               // Access options.
        FILE_SHARE_READ,            // The share mode.
        NULL,                       // Security attributes.
        OPEN_EXISTING,              // Disposition.
        FILE_ATTRIBUTE_NORMAL,      // File attributes.
        NULL                        // The template handle.
        );

    // Check the return.
    if (h_file == INVALID_HANDLE_VALUE)
    {
        // Cannot open the specified file.
        return cobf_error::COBF_CANNOT_OPEN_FILE;
    };

    // Needed local variables.
    PIMAGE_DOS_HEADER dos_hdr;
    PIMAGE_NT_HEADERS nt_hdrs;
    PIMAGE_IMPORT_DESCRIPTOR p_imports;
    size_t imports_size;

    // Getting the size.
    LARGE_INTEGER f_size;
    if (!GetFileSizeEx(h_file, &f_size))
    {
        // Cannot get the file size.
        ret_err = cobf_error::COBF_CANNOT_GET_SIZE;
        goto LOAD_FINISH;
    };

    // Resizing the raw file array.
    this->pe_rawf.resize((size_t)f_size.QuadPart);

    // Reading the file.
    DWORD r_size;
    if (!ReadFile(
        h_file,                     // The PE file handle.
        this->pe_rawf.data(),       // The data of the vector.
        (DWORD)this->pe_rawf.size(),// Size to read.
        &r_size,                    // Read bytes.
        NULL                        // Overlapped struct.
    )) 
    {
        // Cannot read.
        ret_err = cobf_error::COBF_CANNOT_READ_FILE;
        goto LOAD_FINISH;
    };

    // Get the dos header.
    if (!this->get_dos_header(dos_hdr))
    {
        // Invalid dos header.
        ret_err = cobf_error::COBF_INVALID_DOS_HDR;
        goto LOAD_FINISH;
    };

    // Get the dos header.
    if (!this->get_nt_headers(dos_hdr, nt_hdrs))
    {
        // Invalid dos header.
        ret_err = cobf_error::COBF_INVALID_NT_HDRS;
        goto LOAD_FINISH;
    };

    // Verify the arch.
    if (!this->verify_machine(nt_hdrs))
    {
        // Invalid dos header.
        ret_err = cobf_error::COBF_UNSUPPORTED_PE;
        goto LOAD_FINISH;
    };

    // Verify the sections.
    if (!this->verify_sections(dos_hdr, nt_hdrs))
    {
        // Invalid sections header.
        ret_err = cobf_error::COBF_INVALID_SECTION_HDR;
        goto LOAD_FINISH;
    };

    // Get the imports directory.
    if (!this->get_data_table(IMAGE_DIRECTORY_ENTRY_IMPORT, (PVOID*)&p_imports, imports_size))
    {
        // Invalid imports directory.
        ret_err = cobf_error::COBF_INVALID_IMPORTS_DIR;
        goto LOAD_FINISH;
    };

    // Getting the import directory.
    if (p_imports && !this->parse_imports(p_imports, imports_size))
    {
        // Invalid imports.
        ret_err = cobf_error::COBF_CANNOT_PARSE_IMPORTS;
        goto LOAD_FINISH;
    };

LOAD_FINISH:

    // Clearing.
    if (ret_err != cobf_error::COBF_NO_ERROR) 
    {
        // Removing the symbols and the loaded module.
        this->pe_rawf.clear();
        this->pe_mods.clear();
    };

    // Closing the handle.
    if (!CloseHandle(h_file)) return cobf_error::COBF_CANNOT_CLEAR;
    return ret_err;
};

// Unload the specified PE from memory.
cobf_error cobf::unload_pe()
{
    // Check if already unloaded.
    if (this->pe_rawf.empty()) return cobf_error::COBF_PE_UNLOADED;

    // Clear everything.
    this->pe_rawf.clear();
    this->pe_mods.clear();
    return cobf_error::COBF_NO_ERROR;
};

// Get the attributes for the a data table.
BOOL cobf::get_data_table(size_t data_entry, PVOID* p_table_ptr, size_t& table_size)
{
    // Get the headers.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf[dos_hdr->e_lfanew];

    // Check if the index is valid.
    if (data_entry >= nt_hdrs->OptionalHeader.NumberOfRvaAndSizes) return FALSE;

    // Check the table itself.
    DWORD table_rva = nt_hdrs->OptionalHeader.DataDirectory[data_entry].VirtualAddress;
    table_size = nt_hdrs->OptionalHeader.DataDirectory[data_entry].Size;

    // Check if zero.
    if (!table_rva)
    {
        // Zero both of them.
        *p_table_ptr = NULL;
        table_size = 0;
        return TRUE;
    };

    // Convert it to offset.
    DWORD table_offset;
    if (!this->rva_to_offset(table_rva, table_offset)) return FALSE;
    if (table_offset + table_size > this->pe_rawf.size()) return FALSE;

    // Fill the pointer.
    *p_table_ptr = (PVOID)&this->pe_rawf[table_offset];
    return TRUE;
};

// Get the section of some rva.
BOOL cobf::section_of_rva(DWORD rva, PIMAGE_SECTION_HEADER& sec)
{
    // Get the sections.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf[dos_hdr->e_lfanew];
    PIMAGE_SECTION_HEADER c_sec = (PIMAGE_SECTION_HEADER)&this->pe_rawf[dos_hdr->e_lfanew +
        sizeof(nt_hdrs->Signature) + sizeof(nt_hdrs->FileHeader) +
        nt_hdrs->FileHeader.SizeOfOptionalHeader];

    // Loop on the sections.
    WORD n_secs = nt_hdrs->FileHeader.NumberOfSections;
    while (n_secs--)
    {
        // Check if not contained.
        if (rva < (size_t)c_sec->VirtualAddress || rva >= (size_t)c_sec->VirtualAddress +
            c_sec->Misc.VirtualSize)
        {
            // Move to the next one.
            c_sec++;
            continue;
        };

        // Found.
        sec = c_sec;
        return TRUE;
    };

    // Not found.
    return FALSE;
};

// Verify and get the dos header.
BOOL cobf::get_dos_header(PIMAGE_DOS_HEADER& dos_hdr)
{
    // Verifing the dos header.
    dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    if (sizeof(*dos_hdr) > this->pe_rawf.size() ||
        dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    return TRUE;
};

// Verify and get the nt headers.
BOOL cobf::get_nt_headers(PIMAGE_DOS_HEADER dos_hdr, PIMAGE_NT_HEADERS& nt_hdrs)
{
    // Verifing the nt headers.
    nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf[dos_hdr->e_lfanew];
    if (sizeof(*nt_hdrs) + dos_hdr->e_lfanew > this->pe_rawf.size() ||
        nt_hdrs->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    return TRUE;
};

// Verify the archeticture.
BOOL cobf::verify_machine(PIMAGE_NT_HEADERS nt_hdrs)
{
    // Verify the machine.
#ifdef _M_IX86
    return nt_hdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
#else
    return nt_hdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || 
        nt_hdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64;
#endif
};

// Verify the sections.
BOOL cobf::verify_sections(PIMAGE_DOS_HEADER dos_hdr, PIMAGE_NT_HEADERS nt_hdrs)
{
    // Verify the sections header.
    return dos_hdr->e_lfanew + sizeof(*nt_hdrs) + nt_hdrs->FileHeader.NumberOfSections
        * sizeof(IMAGE_SECTION_HEADER) <= this->pe_rawf.size() &&
        nt_hdrs->FileHeader.NumberOfSections;
};

// Parse the imported symbols.
BOOL cobf::parse_imports(PIMAGE_IMPORT_DESCRIPTOR p_imports, size_t imports_size)
{
    // Filling up the imported modules array.
    while (imports_size >= sizeof(IMAGE_IMPORT_DESCRIPTOR) && p_imports->Name)
    {
        // Getting the thunk array offset.
        DWORD dll_name = p_imports->Name;
        DWORD orig_th = p_imports->OriginalFirstThunk;
        DWORD first_th = p_imports->FirstThunk;
        PSIZE_T p_orig_th, p_first_th;
        PCHAR p_dll_name; size_t sym_idx = 0;
       
        // Convert the pointers.
        if ((orig_th && !this->rva_to_ptr(orig_th, (PVOID*)&p_orig_th))
            || !this->rva_to_ptr(first_th, (PVOID*)&p_first_th)
            || !this->rva_to_ptr(dll_name, (PVOID*)&p_dll_name))
        {
            // Cannot get the thunks or the name.
            return FALSE;
        };

        // Get the dll name.
        this->pe_mods.push_back({ p_dll_name });
        auto& dll_mod = this->pe_mods.back();
        transform(dll_mod.dll_name.begin(), dll_mod.dll_name.end(), 
            dll_mod.dll_name.begin(), ::toupper);

        // Loop the imports.
        PSIZE_T p_thunk = orig_th ? p_orig_th : p_first_th;
        while (*p_thunk)
        {
            // Needed attributes.
            DWORD fth_rva = first_th + (DWORD)sym_idx * sizeof(size_t);
            DWORD oth_off = (DWORD)((PBYTE)p_thunk - this->pe_rawf.data());

            // Try to insert it.
            if (!this->insert_import(this->pe_mods.back(), dll_name, *p_thunk, fth_rva, oth_off)) 
                return FALSE;

            // Calculate the next one.
            p_thunk++;
            sym_idx++;
        };

        // Move to the next module.
        imports_size -= sizeof(IMAGE_IMPORT_DESCRIPTOR);
        p_imports++;
    };

    // Done.
    return TRUE;
};

// Insert a parsed import.
BOOL cobf::insert_import(cmod& dll_mod, DWORD dll_off, size_t th_sym, DWORD fth_rva, DWORD oth_off)
{
    // Check if imported by ordinal.
    if (IMAGE_SNAP_BY_ORDINAL(th_sym))
    {
        // Inserting the import.
        dll_mod.mod_syms.push_back(csym(IMAGE_ORDINAL(th_sym), dll_off, fth_rva, oth_off));
        return TRUE;
    };

    // Imported by name.
    PCHAR p_name;
    if (!this->rva_to_ptr((DWORD)th_sym, (PVOID*)&p_name))
    {
        // Invalid rva.
        return FALSE;
    };

    // Inserting the import.
    p_name += sizeof(IMAGE_IMPORT_BY_NAME::Hint);

    // Inserting the import.
    dll_mod.mod_syms.push_back(csym(p_name, dll_off, fth_rva, oth_off,
        (DWORD)((PBYTE)p_name - this->pe_rawf.data())));
    return TRUE;
};

// Convert RVA to pointer after checking it.
BOOL cobf::rva_to_ptr(DWORD ptr_rva, PVOID* p_ptr)
{
    if (!this->rva_to_offset(ptr_rva, ptr_rva) ||
        ptr_rva >= this->pe_rawf.size()) return FALSE;
    *p_ptr = (PVOID)&this->pe_rawf[ptr_rva];
    return TRUE;
};

// Convert RVA to offset.
BOOL cobf::rva_to_offset(DWORD rva, DWORD& offset)
{
    // Get the section.
    PIMAGE_SECTION_HEADER sec;
    if (this->section_of_rva(rva, sec))
    {
        // Convert.
        offset = sec->PointerToRawData + (rva - sec->VirtualAddress);
        return TRUE;
    };

    // Not Converted.
    return FALSE;
};

// Constructor for the obfuscation module.
cobf::cobf(string pe_path) : pe_path(pe_path)
{
    // Seed.
    srand((DWORD)time(NULL));
};

#endif // !LOAD_CPP.