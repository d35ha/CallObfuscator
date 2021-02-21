/*!     @file
 *
 *    This file contains the main functionality
 *    of the obfuscator.
 *
 */

#ifndef OBFUSCATE_CPP
#define OBFUSCATE_CPP

 // The includes.
#include <cobf.hpp>

// Obfuscate one symbol with another.
template <typename t_sym_info, typename t_obf_info>
cobf_error cobf::obf_sym_internal(string dll_name, t_sym_info sym_info, t_obf_info obf_info)
{
    // Convert the name.
    transform(dll_name.begin(), dll_name.end(), dll_name.begin(), ::toupper);

    // Find the symbol.
    vector<csym*> symbols;
    this->find_symbols(dll_name, sym_info, symbols);
    if (symbols.empty()) return cobf_error::COBF_SYMS_NOT_FOUND;

    // Obfuscate it.
    for (auto& symbol : symbols) symbol->obfuscate(obf_info);
    return cobf_error::COBF_NO_ERROR;
};

// Obfuscate one symbol (name) with another (name).
cobf_error cobf::obf_sym(string dll_name, string sym_name, string obf_name) {
    return this->obf_sym_internal(dll_name, sym_name, obf_name);
};

// Obfuscate one symbol (name) with another (ordinal).
cobf_error cobf::obf_sym(string dll_name, string sym_name, WORD obf_ord) {
    return this->obf_sym_internal(dll_name, sym_name, obf_ord);
};

// Obfuscate one symbol (ordinal) with another (ordinal).
cobf_error cobf::obf_sym(string dll_name, WORD sym_ord, WORD obf_ord) {
    return this->obf_sym_internal(dll_name, sym_ord, obf_ord);
};

// Obfuscate one symbol (ordinal) with another (name).
cobf_error cobf::obf_sym(string dll_name, WORD sym_ord, string obf_name) {
    return this->obf_sym_internal(dll_name, sym_ord, obf_name);
};

template <typename t_sym_info>
cobf_error cobf::unobf_sym_internal(string dll_name, t_sym_info sym_info)
{
    // Convert the name.
    transform(dll_name.begin(), dll_name.end(), dll_name.begin(), ::toupper);

    // Find the symbol.
    vector<csym*> symbols;
    this->find_symbols(dll_name, sym_info, symbols);
    if (symbols.empty()) return cobf_error::COBF_SYMS_NOT_FOUND;

    // Unobfuscate it.
    for (auto& symbol : symbols) symbol->unobfuscate();
    return cobf_error::COBF_NO_ERROR;
};

// Unobfuscate one symbol (name).
cobf_error cobf::unobf_sym(string dll_name, string sym_name) {
    return this->unobf_sym_internal(dll_name, sym_name);
};

// Unobfuscate one symbol (ordinal).
cobf_error cobf::unobf_sym(string dll_name, WORD sym_ord) {
    return this->unobf_sym_internal(dll_name, sym_ord);
};

// Generate the obfuscated PE.
cobf_error cobf::generate(string out_file)
{
    // Check if not loaded and getting a copy of the original PE.
    if (this->pe_rawf.empty()) return cobf_error::COBF_PE_UNLOADED;
   
    // Needed locals.
    cobf_error ret_err = cobf_error::COBF_NO_ERROR;
    PIMAGE_SECTION_HEADER sh_sec;
    DWORD stub_entry;
    DWORD funs_table;
    DWORD symbols;
    DWORD written;

    // Open the file.
    HANDLE h_file = CreateFileA(
        out_file.c_str(),           // The PE file path.
        GENERIC_WRITE,              // Access options.
        FILE_SHARE_WRITE,           // The share mode.
        NULL,                       // Security attributes.
        CREATE_ALWAYS,              // Disposition.
        FILE_ATTRIBUTE_NORMAL,      // File attributes.
        NULL                        // The template handle.
    );

    // Check the return.
    if (h_file == INVALID_HANDLE_VALUE)
    {
        // Cannot create the specified file.
        return cobf_error::COBF_CANNOT_CREATE_FILE;
    };

    // Save the original copy.
    auto orig_pe = this->pe_rawf;

    // Creating the shellcode section.
    if (!this->create_shellcode_section(sh_sec, funs_table))
    {
        // Cannot create the section.
        ret_err = cobf_error::COBF_CANNOT_CREATE_SECTION;
        goto OBFUSCATE_FINISH;
    };

    // Applying the obfuscations.
    this->apply_obfuscations(sh_sec, symbols);
    
    // Adding the stub for the shellcode.
    this->add_shellcode_stub(sh_sec, funs_table, symbols, stub_entry);

    // Add the shellcode entry as a tls callback.
    if (!this->add_shellcode_entry(sh_sec, stub_entry))
    {
        // Cannot do it.
        ret_err = cobf_error::COBF_CANNOT_ADD_ENTRY;
        goto OBFUSCATE_FINISH;
    };

    // Make it unrelocatable.
    if (!this->disable_the_relocation())
    {
        // Cannot create the section.
        ret_err = cobf_error::COBF_CANNOT_DISABLE_RELOCS;
        goto OBFUSCATE_FINISH;
    };

    // Make the imports writible.
    if (!this->make_the_iat_writable())
    {
        // Cannot create the section.
        ret_err = cobf_error::COBF_INVALID_IAT_SECTION;
        goto OBFUSCATE_FINISH;
    };

    // Remove the debug symbols.
    if (!this->remove_debug_symbols())
    {
        // Cannot remove the debug symbols.
        ret_err = cobf_error::COBF_CANNOT_REMOVE_DBG_SYMS;
        goto OBFUSCATE_FINISH;
    };

    // Finish everything.
    this->finalize_pe(sh_sec);

    // Write the PE.
    if (!WriteFile(
        h_file,                         // The PE file handle.
        this->pe_rawf.data(),           // The data of the vector.
        (DWORD)this->pe_rawf.size(),    // Size to read.
        &written,                       // Read bytes.
        NULL                            // Overlapped struct.
    ))
    {
        // Cannot write.
        ret_err = cobf_error::COBF_CANNOT_WRITE_FILE;
        goto OBFUSCATE_FINISH;
    };

OBFUSCATE_FINISH:

    // Restore the PE.
    this->pe_rawf = orig_pe;

    // Test if not successful.
    if (!CloseHandle(h_file) || (ret_err != cobf_error::COBF_NO_ERROR && !DeleteFileA(out_file.c_str())))
        ret_err = cobf_error::COBF_CANNOT_CLEAR;
    return ret_err;
};

// Find a symbol by dll and info.
template <typename t_sym_info>
VOID cobf::find_symbols(string dll_name, t_sym_info sym_info, vector<csym*>& p_syms)
{
    // Loop the symbols.
    for (auto& mod : this->pe_mods)
    {
        // Check the module and the symbol.
        if (!csym::match_wildcard(dll_name.c_str(), mod.dll_name.c_str())) continue;
        for (auto& sym : mod.mod_syms) if (sym.check_sym(sym_info)) 
            p_syms.push_back(&sym);
    };
};

// Create a new entry at the sections header.
BOOL cobf::create_shellcode_section(PIMAGE_SECTION_HEADER& sh_sec, DWORD& funs_rva)
{
    // Get the sections.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf.data()[dos_hdr->e_lfanew];

    // Verify the existence of a new section.
    if (nt_hdrs->OptionalHeader.SizeOfHeaders < dos_hdr->e_lfanew + sizeof(nt_hdrs->Signature) +
        sizeof(nt_hdrs->FileHeader) + nt_hdrs->FileHeader.SizeOfOptionalHeader +
        ((size_t)nt_hdrs->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER))
        return FALSE;

    // Get the section of the shellcode.
    sh_sec = (PIMAGE_SECTION_HEADER)&this->pe_rawf[dos_hdr->e_lfanew +
        sizeof(nt_hdrs->Signature) + sizeof(nt_hdrs->FileHeader) +
        nt_hdrs->FileHeader.SizeOfOptionalHeader + nt_hdrs->FileHeader.NumberOfSections *
        sizeof(IMAGE_SECTION_HEADER)];

    // Set the shellcode section properties.
    PIMAGE_SECTION_HEADER prev_sec = sh_sec - 1;
    sh_sec->Name[0] = '.'; sh_sec->Name[1] = 'c';
    sh_sec->Name[2] = 'o'; sh_sec->Name[3] = 'b';
    sh_sec->Name[4] = 'f'; sh_sec->Name[5] = '\0';
    sh_sec->Name[6] = '\0'; sh_sec->Name[7] = '\0';
    sh_sec->NumberOfLinenumbers = 0;
    sh_sec->NumberOfRelocations = 0;
    sh_sec->PointerToRelocations = 0;
    sh_sec->PointerToLinenumbers = 0;
    sh_sec->Misc.VirtualSize = 0;
    sh_sec->SizeOfRawData = shellcode::shellcode_size + sizeof(shellcode::shellcodes_funs);
    sh_sec->PointerToRawData = prev_sec->PointerToRawData + prev_sec->SizeOfRawData;
    sh_sec->VirtualAddress = prev_sec->VirtualAddress + prev_sec->Misc.VirtualSize +
        nt_hdrs->OptionalHeader.SectionAlignment - (prev_sec->Misc.VirtualSize %
        nt_hdrs->OptionalHeader.SectionAlignment);
    sh_sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    nt_hdrs->FileHeader.NumberOfSections++;

    // Set the section info.
    DWORD sh_sec_offset = (DWORD)((PBYTE)sh_sec - this->pe_rawf.data());

    // Resize the whole pe.
    this->pe_rawf.resize(this->pe_rawf.size() + sh_sec->SizeOfRawData + 
        sizeof(shellcode::shellcodes_funs));
    sh_sec = (PIMAGE_SECTION_HEADER)(this->pe_rawf.data() + sh_sec_offset);
    funs_rva = sh_sec->VirtualAddress + shellcode::shellcode_size;

    // Copy the shellcode and the table.
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData, sh_sec->SizeOfRawData,
        shellcode::shellcode_start, shellcode::shellcode_size);
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData + shellcode::shellcode_size,
        sizeof(shellcode::shellcodes_funs), shellcode::shellcodes_funs,
        sizeof(shellcode::shellcodes_funs));

    // Updating the functions offsets.
    PDWORD p_sh_funs = (PDWORD)(this->pe_rawf.data() + sh_sec->PointerToRawData + shellcode::shellcode_size);
    for (size_t idx = 0; idx < sizeof(shellcode::shellcodes_funs) / sizeof(*shellcode::shellcodes_funs); idx++)
    {
        // Update the offset.
        p_sh_funs[idx] += sh_sec->VirtualAddress;
    };

    // Done.
    return TRUE;
};

// Apply the patches to the PE.
VOID cobf::apply_obfuscations(PIMAGE_SECTION_HEADER& sh_sec, DWORD& syms_rva)
{
    // The array of symbols to load.
    vector<BYTE> strings_of_imports;
    vector<shellcode::obfuscated_sym> symbols;

    // Enumerate the obfuscate by name array.
    DWORD c_rva = sh_sec->VirtualAddress + (DWORD_PTR)sh_sec->SizeOfRawData;
    for (auto& mod : this->pe_mods) for (auto& sym : mod.mod_syms) sym.apply_obfuscation(
        this->pe_rawf.data(), c_rva, strings_of_imports, symbols);

    // Set the section info.
    symbols.push_back({ 0 });
    DWORD sh_sec_offset = (DWORD)((PBYTE)sh_sec - this->pe_rawf.data());

    // Resize the whole pe.
    size_t size_of_symbols = symbols.size() * sizeof(shellcode::obfuscated_sym);
    this->pe_rawf.resize(this->pe_rawf.size() + strings_of_imports.size() + size_of_symbols);
    sh_sec = (PIMAGE_SECTION_HEADER)(this->pe_rawf.data() + sh_sec_offset);

    // Copy the strings and the symbols.
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData + sh_sec->SizeOfRawData,
        strings_of_imports.size() + size_of_symbols, strings_of_imports.data(),
        strings_of_imports.size());
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData + sh_sec->SizeOfRawData + 
        strings_of_imports.size(), size_of_symbols, symbols.data(), size_of_symbols);

    // Edit the properties.
    syms_rva = sh_sec->VirtualAddress + sh_sec->SizeOfRawData + (DWORD)strings_of_imports.size();
    sh_sec->SizeOfRawData += (DWORD)strings_of_imports.size() + (DWORD)size_of_symbols;
};

// Add the stub for shellcode.
VOID cobf::add_shellcode_stub(PIMAGE_SECTION_HEADER& sh_sec, DWORD funs_offset, DWORD syms_rva, DWORD& entry)
{
    // Building the stub.
    DWORD shellcode_entry = sh_sec->VirtualAddress + shellcode::shellcode_entry;
    BYTE shellcode_stub[] =
    {
#ifdef _M_IX86
        0x83, 0x7c, 0x24, 0x08, 0x01,               // cmp dword ptr [esp + 8], 0x1;
        0x74, 0x03, 0xc2, 0x0c, 0x00,               // je $+3; ret;
        0xc7, 0x44, 0x24, 0x08,
        ((PBYTE)&funs_offset)[0],
        ((PBYTE)&funs_offset)[1],
        ((PBYTE)&funs_offset)[2],
        ((PBYTE)&funs_offset)[3],                   // mov dword ptr [esp + 8], functions_rva;
        0xc7, 0x44, 0x24, 0x0c,
        ((PBYTE)&syms_rva)[0],
        ((PBYTE)&syms_rva)[1],
        ((PBYTE)&syms_rva)[2],
        ((PBYTE)&syms_rva)[3],                      // mov dword ptr [esp + 12], symbols_rva;
        0x8b, 0x44, 0x24, 0x04,                     // mov eax, dword ptr [esp + 4];
        0x05,
        ((PBYTE)&shellcode_entry)[0],
        ((PBYTE)&shellcode_entry)[1],
        ((PBYTE)&shellcode_entry)[2],
        ((PBYTE)&shellcode_entry)[3],               // add eax, shellcode_entry;
        0xff, 0xe0                                  // jmp eax;
#else
        0x83, 0xfa, 0x01,                           // cmp edx, 0x1;
        0x74, 0x01, 0xc3,                           // je $+1; ret;
        0x48, 0xc7, 0xc2,
        ((PBYTE)&funs_offset)[0],
        ((PBYTE)&funs_offset)[1],
        ((PBYTE)&funs_offset)[2],
        ((PBYTE)&funs_offset)[3],                   // mov rdx, functions_rva;
        0x41, 0xb8,
        ((PBYTE)&syms_rva)[0],
        ((PBYTE)&syms_rva)[1],
        ((PBYTE)&syms_rva)[2],
        ((PBYTE)&syms_rva)[3],                      // mov r8, symbols_rva;
        0x48, 0x89, 0xc8,                           // mov rax, rcx;
        0x48, 0x05,
        ((PBYTE)&shellcode_entry)[0],
        ((PBYTE)&shellcode_entry)[1],
        ((PBYTE)&shellcode_entry)[2],
        ((PBYTE)&shellcode_entry)[3],               // add rax, shellcode_entry;
        0xff, 0xe0                                  // jmp rax;
#endif // _M_IX86
    };

    // Set the section info.
    DWORD sh_sec_offset = (DWORD)((PBYTE)sh_sec - this->pe_rawf.data());
    DWORD padding_size = 0x10 - sh_sec->SizeOfRawData % 0x10;

    // Resize the whole pe.
    this->pe_rawf.resize(this->pe_rawf.size() + sizeof(shellcode_stub) + padding_size);
    sh_sec = (PIMAGE_SECTION_HEADER)(this->pe_rawf.data() + sh_sec_offset);

    // Copy the stub.
    memset(this->pe_rawf.data() + sh_sec->PointerToRawData + sh_sec->SizeOfRawData, 0xcc,
        padding_size);
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData + sh_sec->SizeOfRawData +
        padding_size, sizeof(shellcode_stub), shellcode_stub, sizeof(shellcode_stub));

    // Update the section.
    entry = sh_sec->VirtualAddress + sh_sec->SizeOfRawData + padding_size;
    sh_sec->SizeOfRawData += sizeof(shellcode_stub) + padding_size;
};

// Disable the relocations at the PE.
BOOL cobf::disable_the_relocation()
{
    // Get the headers.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf.data()[dos_hdr->e_lfanew];

    // Get the table.
    PIMAGE_RESOURCE_DIRECTORY p_relocs; size_t relocs_size;
    if (!this->get_data_table(IMAGE_DIRECTORY_ENTRY_BASERELOC, (PVOID*)&p_relocs, relocs_size))
    {
        // Cannot verify the relocations.
        return FALSE;
    };

    // Zero it.
    if (p_relocs) ZeroMemory(p_relocs, relocs_size);
    nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0, 0 };

    // Stop the relocations.
    nt_hdrs->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

    // Configure the sections.
    PIMAGE_SECTION_HEADER c_sec = (PIMAGE_SECTION_HEADER)&this->pe_rawf[dos_hdr->e_lfanew + 
        sizeof(nt_hdrs->Signature) + sizeof(nt_hdrs->FileHeader) +
        nt_hdrs->FileHeader.SizeOfOptionalHeader];
    for (size_t idx = 0; idx < nt_hdrs->FileHeader.NumberOfSections; idx++)
    {
        // Strip all of the information.
        c_sec[idx].PointerToRelocations = 0;
        c_sec[idx].NumberOfRelocations = 0;
    };

    return TRUE;
};

// Strip any debug symbols from the PE.
BOOL cobf::remove_debug_symbols()
{
    // Get the headers.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf.data()[dos_hdr->e_lfanew];

    // Get the table.
    PIMAGE_DEBUG_DIRECTORY p_debug; size_t debug_size;
    if (!this->get_data_table(IMAGE_DIRECTORY_ENTRY_DEBUG, (PVOID*)&p_debug, debug_size))
    {
        // Cannot verify the debug table.
        return FALSE;
    };

    // Zero it.
    if (p_debug) ZeroMemory(p_debug, debug_size);
    nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = { 0, 0 };

    // Strip it.
    nt_hdrs->FileHeader.NumberOfSymbols = 0;
    nt_hdrs->FileHeader.PointerToSymbolTable = 0;

    // Configure the sections.
    PIMAGE_SECTION_HEADER c_sec = (PIMAGE_SECTION_HEADER)&this->pe_rawf[dos_hdr->e_lfanew +
        sizeof(nt_hdrs->Signature) + sizeof(nt_hdrs->FileHeader) +
        nt_hdrs->FileHeader.SizeOfOptionalHeader];
    for (size_t idx = 0; idx < nt_hdrs->FileHeader.NumberOfSections; idx++)
    {
        // Strip all of the information.
        c_sec[idx].PointerToLinenumbers = 0;
        c_sec[idx].NumberOfLinenumbers = 0;
    };

    return TRUE;
};

// Make the import table section writable for the shellcode.
BOOL cobf::make_the_iat_writable()
{
    // Get the headers.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf.data()[dos_hdr->e_lfanew];

    // Get the table.
    PIMAGE_SECTION_HEADER imports_sec;
    if (!this->section_of_rva(nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT
        ].VirtualAddress, imports_sec))
    {
        // Cannot verify the imports.
        return FALSE;
    };

    // Change the protection.
    imports_sec->Characteristics |= IMAGE_SCN_MEM_WRITE;
    return TRUE;
};

// Add the shellcode entry as a callback.
BOOL cobf::add_shellcode_entry(PIMAGE_SECTION_HEADER& sh_sec, DWORD entry)
{
    // Get the headers.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf.data()[dos_hdr->e_lfanew];

    // Build the array of addresses.
    vector<PVOID> tls_cbs = { (PVOID)(nt_hdrs->OptionalHeader.ImageBase + entry) };
    vector<BYTE> tls_data;

    // Get the table.
    PIMAGE_TLS_DIRECTORY p_tls; size_t tls_size;
    if (!this->get_data_table(IMAGE_DIRECTORY_ENTRY_TLS, (PVOID*)&p_tls, tls_size))
    {
        // Cannot verify the tls table.
        return FALSE;
    };

    // The tls directory can be existing or not.
    if (p_tls)
    {
        // Get the offset to the array.
        DWORD tls_cbs_off = (DWORD)(p_tls->AddressOfCallBacks - nt_hdrs->OptionalHeader.ImageBase);
        if (!this->rva_to_offset(tls_cbs_off, tls_cbs_off)) return FALSE;

        // Adding the availible callbacks.
        PVOID* p_tls_cbs = (PVOID*)&this->pe_rawf[tls_cbs_off];

        // Insert and remove the old pointer.
        do { tls_cbs.push_back(*p_tls_cbs);
        } while (*p_tls_cbs && (*p_tls_cbs++ = NULL, TRUE));

        // Removing the old array and pointer.
        p_tls->AddressOfCallBacks = nt_hdrs->OptionalHeader.ImageBase + sh_sec->VirtualAddress +
            sh_sec->SizeOfRawData;
    }
    else
    {
        // Building a new tls directory.
        IMAGE_TLS_DIRECTORY tls_dir = { 0 }; DWORD index = 0;
        tls_dir.AddressOfIndex = nt_hdrs->OptionalHeader.ImageBase + sh_sec->VirtualAddress +
            sh_sec->SizeOfRawData + sizeof(tls_dir);
        tls_dir.AddressOfCallBacks = tls_dir.AddressOfIndex + sizeof(index);

        // Build up the bytes array.
        tls_data.insert(tls_data.end(), (PBYTE)&tls_dir, (PBYTE)&tls_dir + sizeof(tls_dir));
        tls_data.insert(tls_data.end(), (PBYTE)&index, (PBYTE)&index + sizeof(index));
        tls_cbs.push_back(NULL);

        // Point to the new table.
        nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
            sh_sec->VirtualAddress + sh_sec->SizeOfRawData,
            (DWORD)(sizeof(tls_dir) + sizeof(index) + tls_cbs.size() * sizeof(PVOID))
        };
    };

    // Writing to the shellcode section.
    DWORD sh_sec_offset = (DWORD)((PBYTE)sh_sec - this->pe_rawf.data());

    // Resize the whole pe.
    this->pe_rawf.resize(this->pe_rawf.size() + tls_data.size() + tls_cbs.size() * sizeof(PVOID));
    sh_sec = (PIMAGE_SECTION_HEADER)(this->pe_rawf.data() + sh_sec_offset);

    // Copy the stub.
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData + sh_sec->SizeOfRawData,
        tls_data.size() + tls_cbs.size() * sizeof(PVOID), tls_data.data(), tls_data.size());
    memcpy_s(this->pe_rawf.data() + sh_sec->PointerToRawData + sh_sec->SizeOfRawData + tls_data.size(),
        tls_cbs.size() * sizeof(PVOID), tls_cbs.data(), tls_cbs.size() * sizeof(PVOID));

    // Update the section.
    sh_sec->SizeOfRawData += (DWORD)(tls_data.size() + tls_cbs.size() * sizeof(PVOID));
    return TRUE;
};

// Finalize the obfuscated PE.
VOID cobf::finalize_pe(PIMAGE_SECTION_HEADER& sh_sec)
{
    // Get the sections.
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)this->pe_rawf.data();
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)&this->pe_rawf.data()[dos_hdr->e_lfanew];

    // Calculate the needed size.
    size_t gap_size = nt_hdrs->OptionalHeader.FileAlignment - (sh_sec->SizeOfRawData %
        nt_hdrs->OptionalHeader.FileAlignment);

    // Set the section info.
    DWORD sh_sec_offset = (DWORD)((PBYTE)sh_sec - this->pe_rawf.data());

    // Resize the whole pe.
    this->pe_rawf.resize((size_t)sh_sec->PointerToRawData + (size_t)sh_sec->SizeOfRawData + gap_size);
    sh_sec = (PIMAGE_SECTION_HEADER)(this->pe_rawf.data() + sh_sec_offset);

    // Update the section information.
    sh_sec->Misc.VirtualSize = sh_sec->SizeOfRawData;
    sh_sec->SizeOfRawData += (DWORD)gap_size;
    nt_hdrs->OptionalHeader.SizeOfImage += sh_sec->Misc.VirtualSize + nt_hdrs->OptionalHeader.SectionAlignment -
        (sh_sec->Misc.VirtualSize % nt_hdrs->OptionalHeader.SectionAlignment);
    nt_hdrs->OptionalHeader.CheckSum = 0;
};

// Matching with the module name or any symbol.
BOOL cobf::csym::match_wildcard(PCCH wild_card, PCCH string)
{
    // Init.
    PCCH s_wild;
    PCCH s_str;
    BOOL wild = FALSE;

loop_start:
    for (s_wild = wild_card, s_str = string; *s_str; ++s_str, ++s_wild) {
        if (*s_wild == '*')
        {
            // Found a wildcard.
            wild = TRUE;
            string = s_str, wild_card = s_wild;

            // Overlooking any consecutive wildcards.
            do { ++wild_card; } while (*wild_card == '*');

            // Reached the end of the wildcard string.
            if (!*wild_card) return TRUE;
            goto loop_start;
        }
        // Default match.
        else if (*s_wild != *s_str) goto wild_check;
    };
    while (*s_wild == '*') ++s_wild;
    return (!*s_wild);

wild_check:
    // Move to next char.
    if (!wild) return FALSE;
    string++;
    goto loop_start;
};

// Check the symbol name.
BOOL cobf::csym::check_sym(string n_sym)
{
    // Extra check if imported by name.
    return this->by_name && match_wildcard(n_sym.c_str(), 
        this->sym_name.c_str());
};

// Check the symbol ordinal.
BOOL cobf::csym::check_sym(WORD n_ord)
{
    // Extra check if imported by ordinal.
    return !this->by_name && this->sym_ord == n_ord;
};

// Obfuscate by name.
VOID cobf::csym::obfuscate(string o_sym)
{
    // Obfuscate.
    this->obf_name = o_sym;
    this->to_name = TRUE;
    this->obfuscated = TRUE;
};

// Obfuscate by ordinal.
VOID cobf::csym::obfuscate(WORD o_ord)
{
    // Obfuscate.
    this->obf_ord = o_ord;
    this->to_name = FALSE;
    this->obfuscated = TRUE;
};

// Unobfuscate.
VOID cobf::csym::unobfuscate()
{
    // Unbfuscate.
    this->obfuscated = FALSE;
};

// Apply the obfuscation.
VOID cobf::csym::apply_obfuscation(PBYTE pe_rawf, DWORD strings_off, vector<BYTE>& strings,
    vector<shellcode::obfuscated_sym>& symbols)
{
    // Check if not obfuscated.
    if (!this->obfuscated) return;

    // Build the symbol.
    shellcode::obfuscated_sym symbol;
    symbol.dll_name = this->dll_rva;
    symbol.sym_thnk = this->fth_rva;

    // Test if imported by name.
    if (symbol.by_name = this->by_name)
    {
        // Imported by name.
        symbol.sym_info.sym_hash = shellcode::hash_string((PCHAR)this->sym_name.c_str());

        // Removing the old name.
        for (size_t idx = 0; idx < this->sym_name.size() + sizeof(CHAR); idx++)
        {
            // Randomize it.
            pe_rawf[this->name_off + idx] = rand();
        };
    }
    // Imported by ordinal.
    else symbol.sym_info.sym_ord = this->obf_ord;

    // Calculating the thunk data.
    PVOID thunk_data;
    if (this->to_name)
    {
        // Obfuscated to name.
        thunk_data = (PVOID)(strings_off + strings.size());

        // Append a new import by name struct.
        strings.push_back(rand());
        strings.push_back(rand());
        strings.insert(strings.end(), this->obf_name.data(),
            this->obf_name.data() + this->obf_name.size() + 
            sizeof(CHAR));
    }
    // Obfuscated to ordinal.
    else thunk_data = (PVOID)(this->obf_ord | IMAGE_ORDINAL_FLAG);

    // Save the symbol.
    symbols.push_back(symbol);
    *(PVOID*)&pe_rawf[this->oth_off] = thunk_data;
};

// Constructor.
cobf::csym::csym(string sym_name, DWORD dll_rva, DWORD fth_rva, DWORD oth_off, DWORD name_off) 
    : sym_name(sym_name), dll_rva(dll_rva), fth_rva(fth_rva), oth_off(oth_off), name_off(name_off)
{
    // Init.
    this->by_name = TRUE;
    this->sym_ord = 0;
    this->obfuscated = FALSE;
    this->obf_ord = 0;
    this->to_name = FALSE;
};

// Constructor.
cobf::csym::csym(WORD sym_ord, DWORD dll_rva, DWORD fth_rva, DWORD oth_off) :
    sym_ord(sym_ord), dll_rva(dll_rva), fth_rva(fth_rva), oth_off(oth_off)
{
    // Init.
    this->by_name = FALSE;
    this->obfuscated = FALSE;
    this->obf_ord = 0;
    this->to_name = FALSE;
    this->name_off = 0;
};

#endif // !OBFUSCATE_CPP.