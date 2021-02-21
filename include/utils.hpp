
/*!     @file
 *
 *      This file contains the utilities 
 *      used by the library. 
 */


#ifndef UTILS_HPP
#define UTILS_HPP

/*!     @ingroup  COBF
*       Errors reported by the library.
*/
enum class cobf_error {
    COBF_NO_ERROR,              /*!< The operation was successfull. */
    COBF_CANNOT_OPEN_FILE,      /*!< Cannot open the file from the disk. */
    COBF_CANNOT_CREATE_FILE,    /*!< Cannot create the file to the disk. */
    COBF_CANNOT_GET_SIZE,       /*!< Cannot get the file size. */
    COBF_CANNOT_READ_FILE,      /*!< Cannot read the file data. */
    COBF_INVALID_DOS_HDR,       /*!< The dos header cannot be verified. */
    COBF_INVALID_NT_HDRS,       /*!< The nt headers cannot be verified. */
    COBF_UNSUPPORTED_PE,        /*!< The PE type is not supported. */
    COBF_INVALID_SECTION_HDR,   /*!< The sections header cannot be verified. */
    COBF_INVALID_IMPORTS_DIR,   /*!< The imports directory cannot be verified. */
    COBF_CANNOT_PARSE_IMPORTS,  /*!< Unable to parse all of the imported symbols. */
    COBF_CANNOT_WRITE_FILE,     /*!< Cannot write to the file. */
    COBF_CANNOT_CLEAR,          /*!< Cannot close the file handle. */
    COBF_CANNOT_CREATE_SECTION, /*!< Cannot create a new section for the shellcode. */
    COBF_CANNOT_ADD_ENTRY,      /*!< Cannot add the entry of the shellcode as a callback. */
    COBF_CANNOT_DISABLE_RELOCS, /*!< Cannot remove the relocations from the PE. */
    COBF_INVALID_IAT_SECTION,   /*!< Cannot get the section of the import table. */
    COBF_CANNOT_REMOVE_DBG_SYMS,/*!< Cannot remove the symbols table. */
    COBF_MODULE_NOT_FOUND,      /*!< The module was not found. */
    COBF_PE_LOADED,             /*!< The PE is already loaded. */
    COBF_PE_UNLOADED,           /*!< The PE is already unloaded. */
    COBF_SYMS_NOT_FOUND         /*!< The symbol(s) couldn't be found. */
};

/*!     @ingroup        UTILS
*       @brief          Format the error to a message.
*       @param[in]      err_msg The error to convert.
*       @param[in]      buffer The buffer to receive the data.
*       @param[in]      size The size of the buffer.
*/
void cobf_format_message(cobf_error err_msg, char* buffer, unsigned int size);

#endif // !UTILS_HPP.