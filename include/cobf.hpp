
/*!     @file
 *
 *      This file contains the main functionality
 *      of the obfuscator (declartions only).
 *
 */

#ifndef COBF_HPP
#define COBF_HPP

// Includes.
#include <shellcode.hpp>
#include <utils.hpp>
#include <algorithm>
#include <string>
#include <vector>
#include <map>
using namespace std;

/*!     @ingroup    COBF
 *      The main obfuscator class, holds the needed 
 *      load, configure and obfuscate the input PE.
 */
class cobf
{
private:

    // Each symbol.
    class csym {
    private:

        string          sym_name;       /*!< The name of the symbol. */
        DWORD           dll_rva;        /*!< Rva to the dll name */
        WORD            sym_ord;        /*!< The ordinal of the symbol. */
        DWORD           fth_rva;        /*!< Rva to the first thunk symbol entry */
        DWORD           oth_off;        /*!< Offset to the original thunk symbol entry */
        DWORD           name_off;       /*!< Offset to the symbol name */
        BOOL            by_name;        /*!< If imported by name. */
        BOOL            obfuscated;     /*!< If requested to be obfuscated. */
        string          obf_name;       /*!< The name to obfuscated with. */
        WORD            obf_ord;        /*!< The ordinal to obfuscate with. */
        BOOL            to_name;        /*!< If obfuscated to name. */

    public:

        /*!     @ingroup        CSYM
         *      @brief          Matching with the module name or any symbol.
         *      @param[in]      wild_card String to match with (contains *).
         *      @param[in]      string RVA to get.
         *      @return         True if matched.
         */
        static BOOL match_wildcard(PCCH wild_card, PCCH string);

        /*!     @ingroup        CSYM
         *      @brief          Constructor.
         *      @param[in]      sym_name The symbol name.
         *      @param[in]      dll_rva The dll name rva.
         *      @param[in]      fth_rva The first thunks symbol entry.
         *      @param[in]      oth_off The original thunks symbol entry.
         *      @param[in]      name_off Offset to the name string.
         */
        csym(string sym_name, DWORD dll_rva, DWORD fth_rva, DWORD oth_off, DWORD name_off);

        /*!     @ingroup        CSYM
         *      @brief          Constructor.
         *      @param[in]      sym_ord The symbol ordinal.
         *      @param[in]      dll_rva The dll name rva.
         *      @param[in]      fth_rva The first thunks symbol entry.
         *      @param[in]      oth_off The original thunks symbol entry.
         */
        csym(WORD sym_ord, DWORD dll_rva, DWORD fth_rva, DWORD oth_off);

        /*!     @ingroup        CSYM
         *      @brief          Check the symbol name.
         *      @param[in]      n_sym Symbol name to check.
         *      @return         True if checked.
         */
        BOOL check_sym(string n_sym);

        /*!     @ingroup        CSYM
         *      @brief          Check the symbol ordinal.
         *      @param[in]      n_ord Ordinal to check.
         *      @return         True if checked.
         */
        BOOL check_sym(WORD n_ord);

        /*!     @ingroup        CSYM
         *      @brief          Obfuscate by name.
         *      @param[in]      o_sym Symbol name to obfuscate with.
         */
        VOID obfuscate(string o_sym);

        /*!     @ingroup        CSYM
         *      @brief          Obfuscate by ordinal.
         *      @param[in]      o_ord Symbol ordinal to obfuscate with.
         */
        VOID obfuscate(WORD o_ord);

        /*!     @ingroup        CSYM
         *      @brief          Unobfuscate.
         */
        VOID unobfuscate();

        /*!     @ingroup        CSYM
         *      @brief          Apply the obfuscation.
         *      @param[in]      pe_rawf The PE raw file data.
         *      @param[in]      strings_off The offset of the strings inside the PE.
         *      @param[in]      strings Filled with the new strings.
         *      @param[in]      symbols Filled with the built obfuscated symbols.
         */
        VOID apply_obfuscation(PBYTE pe_rawf, DWORD strings_off, vector<BYTE>& strings,
            vector<shellcode::obfuscated_sym>& symbols);
    };

    // Each module.
    struct cmod {
        string          dll_name;       /*!< The name of the dll. */
        vector<csym>    mod_syms;       /*!< All of the imported symbols. */
    };

    string          pe_path;    /*!< The path of the portable executable. */
    vector<BYTE>    pe_rawf;    /*!< The raw data for the pe file. */
    vector<cmod>    pe_mods;    /*!< All of the imported modules. */
    
    /*!     @ingroup        COBF
     *      @brief          Disable the relocations at the PE.
     *      @return         True if succeeded.
     */
    BOOL disable_the_relocation();

    /*!     @ingroup        COBF
     *      @brief          Strip any debug symbols from the PE.
     *      @return         True if succeeded.
     */
    BOOL remove_debug_symbols();

    /*!     @ingroup        COBF
     *      @brief          Make the import table section writable for the shellcode.
     *      @return         True if succeeded.
     */
    BOOL make_the_iat_writable();

    /*!     @ingroup        COBF
     *      @brief          Find a symbol by dll and info.
     *      @param[in]      dll_name The dll name.
     *      @param[in]      sym_info The name or the ordinal.
     *      @param[out]     p_syms Receives the pointers to the symbols.
     *      @return         True if succeeded.
     */
    template <typename t_sym_info>
    VOID find_symbols(string dll_name, t_sym_info sym_info, vector<csym*>& p_syms);

    /*!     @ingroup        COBF
     *      @brief          Add the shellcode entry as a callback.
     *      @param[in,out]  sh_sec The shellcode section.
     *      @param[in]      entry The shellcode entry point rva.
     *      @return         True if succeeded.
     */
    BOOL add_shellcode_entry(PIMAGE_SECTION_HEADER& sh_sec, DWORD entry);
    
    /*!     @ingroup        COBF
     *      @brief          Get the section of some rva.
     *      @param[in]      rva RVA to get.
     *      @param[out]     sec Section to query.
     *      @return         True if found.
     */
    BOOL section_of_rva(DWORD rva, PIMAGE_SECTION_HEADER& sec);

    /*!     @ingroup    COBF
     *      @brief      Convert RVA to offset.
     *      @param[in]  rva RVA to convert.
     *      @param[out] offset Receives the offset.
     *      @return     True if converted.
     */
    BOOL rva_to_offset(DWORD rva, DWORD& offset);

    /*!     @ingroup    COBF
     *      @brief      Convert RVA to pointer after checking it.
     *      @param[in]  ptr_rva RVA to be converted.
     *      @param[out] p_ptr Receives the pointer.
     *      @return     True if converted.
     */
    BOOL rva_to_ptr(DWORD ptr_rva, PVOID* p_ptr);

    /*!     @ingroup    COBF
     *      @brief      Create a new entry at the sections header.
     *      @param[out] sh_sec Receives the pointer to the entry.
     *      @param[out] funs_rva Receives the rva to the functions table.
     *      @return     True if succeeded.
     */
    BOOL create_shellcode_section(PIMAGE_SECTION_HEADER& sh_sec, DWORD& funs_rva);

    /*!     @ingroup        COBF
     *      @brief          Get the attributes for the a data table.
     *      @param[in]      data_entry The index inside the table.
     *      @param[out]     p_table_ptr Receives the pointer to the table (can be null).
     *      @param[out]     table_size Receives the size of the table.
     *      @return         True if verified (found or not found).
     */
    BOOL get_data_table(size_t data_entry, PVOID* p_table_ptr, size_t& table_size);

    /*!     @ingroup        COBF
     *      @brief          Verify and get the dos header.
     *      @param[out]     dos_hdr Receives the pointer to the dos header.
     *      @return         True if verified.
     */
    BOOL get_dos_header(PIMAGE_DOS_HEADER& dos_hdr);

    /*!     @ingroup        COBF
     *      @brief          Verify and get the nt headers.
     *      @param[in]      dos_hdr The dos header.
     *      @param[out]     nt_hdrs Receives the pointer to the nt headers.
     *      @return         True if verified.
     */
    BOOL get_nt_headers(PIMAGE_DOS_HEADER dos_hdr, PIMAGE_NT_HEADERS& nt_hdrs);

    /*!     @ingroup        COBF
     *      @brief          Verify the architecture.
     *      @param[in]      nt_hdrs The nt header.
     *      @return         True if verified.
     */
    BOOL verify_machine(PIMAGE_NT_HEADERS nt_hdrs);

    /*!     @ingroup        COBF
     *      @brief          Verify the sections header.
     *      @param[in]      dos_hdr The dos header.
     *      @param[in]      nt_hdrs The nt header.
     *      @return         True if verified.
     */
    BOOL verify_sections(PIMAGE_DOS_HEADER dos_hdr, PIMAGE_NT_HEADERS nt_hdrs);

    /*!     @ingroup        COBF
     *      @brief          Insert a parsed import.
     *      @param[in]      dll_mod The dll module of the imported symbol.
     *      @param[in]      dll_off Offset of the dll name.
     *      @param[in]      th_sym Thunk data of the imported symbol.
     *      @param[in]      fth_rva Rva to the entry of the first thunk of the symbol.
     *      @param[in]      oth_off Rva to the entry of the original thunk of the symbol.
     *      @return         True if inserted.
     */
    BOOL insert_import(cmod& dll_mod, DWORD dll_off, size_t th_sym, DWORD fth_rva, DWORD oth_off);

    /*!     @ingroup        COBF
     *      @brief          Parse the imported symbols.
     *      @param[in]      p_imports Pointer to the imports directory.
     *      @param[in]      imports_size The imports directory size.
     *      @return         True if parsed.
     */
    BOOL parse_imports(PIMAGE_IMPORT_DESCRIPTOR p_imports, size_t imports_size);

    /*!     @ingroup        COBF
     *      @brief          Apply the patches to the PE.
     *      @param[in,out]  sh_sec The shellcode section.
     *      @param[out]     syms_rva The rva of the symbols table.
     */
    VOID apply_obfuscations(PIMAGE_SECTION_HEADER& sh_sec, DWORD& syms_rva);

    /*!     @ingroup        COBF
     *      @brief          Add the stub for shellcode.
     *      @param[in,out]  sh_sec The shellcode section.
     *      @param[in]      funs_rva Receives the rva to the functions table.
     *      @param[in]      syms_rva The rva of the symbols table.
     *      @param[out]     entry Receives the rva of the shellcode stub entry point.
     */
    VOID add_shellcode_stub(PIMAGE_SECTION_HEADER& sh_sec, DWORD funs_offset, DWORD syms_rva, DWORD& entry);

    /*!     @ingroup        COBF
     *      @brief          Finalize the obfuscated PE.
     *      @param[in,out]  sh_sec The shellcode section.
     */
    VOID finalize_pe(PIMAGE_SECTION_HEADER& sh_sec);

    /*!     @ingroup    COBF
     *      @brief      Obfuscate one symbol with another.
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_info The symbol to unobfuscate.
     *      @param[in]  obf_info The new symbol to obfuscate with.
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    template <typename t_sym_info, typename t_obf_info>
    cobf_error obf_sym_internal(string dll_name, t_sym_info sym_info, t_obf_info obf_info);

    /*!     @ingroup    COBF
     *      @brief      Unobfuscate one symbol.
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_info The symbol to unobfuscate.
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    template <typename t_sym_info>
    cobf_error unobf_sym_internal(string dll_name, t_sym_info sym_info);

public:
    /*!     @ingroup    COBF
     *      @brief      Constructor for the obfuscation module.
     *      @param[in]  pe_path Path of the PE file to obfuscate.
     *      @return     The instance.
     */
    cobf(string pe_path);

    /*!     @ingroup    COBF
     *      @brief      Load the specified PE from disk.
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_PE_LOADED if the PE is already loaded.
     *                  COBF_CANNOT_OPEN_FILE if the file cannot be opened.
     *                  COBF_CANNOT_GET_SIZE if the loader cannot get the size.
     *                  COBF_CANNOT_READ_FILE if the loaded cannot read the file.
     *                  COBF_INVALID_DOS_HDR if the PE has invalid dos header.
     *                  COBF_INVALID_NT_HDRS if the PE has invalid nt headers.
     *                  COBF_UNSUPPORTED_PE if the PE type is unsupported.
     *                  COBF_INVALID_SECTION_HDR if the PE has invalid section header.
     *                  COBF_INVALID_IMPORTS_DIR if the PE has invalid imports directory.
     *                  COBF_CANNOT_PARSE_IMPORTS if the parser cannot parse all of the symbols.
     *                  COBF_CANNOT_CLEAR if cannot clear the resources.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error load_pe();

    /*!     @ingroup    COBF
     *      @brief      Unload the specified PE from memory.
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_PE_UNLOADED if the PE is already unloaded.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error unload_pe();

    /*!     @ingroup    COBF
     *      @brief      Obfuscate one symbol (name) with another (name).
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_name The symbol to unobfuscate (name).
     *      @param[in]  obf_name The new symbol to obfuscate with (name).
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error obf_sym(string dll_name, string sym_name, string obf_name);

    /*!     @ingroup    COBF
     *      @brief      Obfuscate one symbol (name) with another (ordinal).
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_name The symbol to unobfuscate (name).
     *      @param[in]  obf_ord The new symbol to obfuscate with (ordinal).
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error obf_sym(string dll_name, string sym_name, WORD obf_ord);

    /*!     @ingroup    COBF
     *      @brief      Obfuscate one symbol (ordinal) with another (ordinal).
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_ord The symbol to unobfuscate (ordinal).
     *      @param[in]  obf_ord The new symbol to obfuscate with (ordinal).
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error obf_sym(string dll_name, WORD sym_ord, WORD obf_ord);

    /*!     @ingroup    COBF
     *      @brief      Obfuscate one symbol (ordinal) with another (name).
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_ord The symbol to unobfuscate (ordinal).
     *      @param[in]  obf_name The new symbol to obfuscate with (name).
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error obf_sym(string dll_name, WORD sym_ord, string obf_name);

    /*!     @ingroup    COBF
     *      @brief      Unobfuscate one symbol (name).
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_name The symbol to unobfuscate (name).
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error unobf_sym(string dll_name, string sym_name);

    /*!     @ingroup    COBF
     *      @brief      Unobfuscate one symbol (ordinal).
     *      @param[in]  dll_name The dll name.
     *      @param[in]  sym_ord The symbol to unobfuscate (ordinal).
     *      @return     COBF_NO_ERROR if done successfully.
     *                  COBF_SYMS_NOT_FOUND if the symbol is not imported.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error unobf_sym(string dll_name, WORD sym_ord);

    /*!     @ingroup    COBF
     *      @brief      Generate the obfuscated PE.
     *      @param[in]  out_file The file to write to.
     *      @return     COBF_NO_ERROR  if done successfully.
     *                  COBF_PE_UNLOADED if the PE is not loaded.
     *                  COBF_CANNOT_CREATE_FILE if unable to create the file.
     *                  COBF_CANNOT_ADD_ENTRY if cannot register the shellcode entry.
     *                  COBF_CANNOT_DISABLE_RELOCS if cannot strip the relocations.
     *                  COBF_INVALID_IAT_SECTION if the IAT table is invalid.
     *                  COBF_CANNOT_REMOVE_DBG_SYMS if unable to strip the symbols.
     *                  COBF_CANNOT_WRITE_FILE if cannot write to the file.
     *                  COBF_CANNOT_CLEAR if cannot clear the resources.
     *      @note       It's not thread-safe, be cautious.
     */
    cobf_error generate(string out_file);
};

#endif // !COBF_HPP.