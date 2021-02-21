/*!     @file
 *
 *      This file contains the utilities
 *      used by the library (source code).
 */

#ifndef UTILS_CPP
#define UTILS_CPP

// Includes.
#include <utils.hpp>
#include <string.h>

// Format the error to a message.
void cobf_format_message(cobf_error err_msg, char* buffer, unsigned int size)
{
	// Switching.
	switch (err_msg)
	{
	case cobf_error::COBF_NO_ERROR:              strcpy_s(buffer, size, "The operation was successfull."); break;
	case cobf_error::COBF_CANNOT_OPEN_FILE:      strcpy_s(buffer, size, "Cannot open the file from the disk."); break;
	case cobf_error::COBF_CANNOT_CREATE_FILE:    strcpy_s(buffer, size, "Cannot create the file to the disk."); break;
	case cobf_error::COBF_CANNOT_GET_SIZE:       strcpy_s(buffer, size, "Cannot get the file size."); break;
	case cobf_error::COBF_CANNOT_READ_FILE:      strcpy_s(buffer, size, "Cannot read the file data."); break;
	case cobf_error::COBF_INVALID_DOS_HDR:       strcpy_s(buffer, size, "The dos header cannot be verified."); break;
	case cobf_error::COBF_INVALID_NT_HDRS:       strcpy_s(buffer, size, "The nt headers cannot be verified."); break;
	case cobf_error::COBF_UNSUPPORTED_PE:        strcpy_s(buffer, size, "The PE type is not supported."); break;
	case cobf_error::COBF_INVALID_SECTION_HDR:   strcpy_s(buffer, size, "The sections header cannot be verified."); break;
	case cobf_error::COBF_INVALID_IMPORTS_DIR:   strcpy_s(buffer, size, "The imports directory cannot be verified."); break;
	case cobf_error::COBF_CANNOT_PARSE_IMPORTS:  strcpy_s(buffer, size, "Unable to parse all of the imported symbols."); break;
	case cobf_error::COBF_CANNOT_WRITE_FILE:     strcpy_s(buffer, size, "Cannot write to the file."); break;
	case cobf_error::COBF_CANNOT_CLEAR:          strcpy_s(buffer, size, "Cannot close the file handle."); break;
	case cobf_error::COBF_CANNOT_CREATE_SECTION: strcpy_s(buffer, size, "Cannot create a new section for the shellcode."); break;
	case cobf_error::COBF_CANNOT_ADD_ENTRY:      strcpy_s(buffer, size, "Cannot add the entry of the shellcode as a callback."); break;
	case cobf_error::COBF_CANNOT_DISABLE_RELOCS: strcpy_s(buffer, size, "Cannot remove the relocations from the PE."); break;
	case cobf_error::COBF_INVALID_IAT_SECTION:   strcpy_s(buffer, size, "Cannot get the section of the import table."); break;
	case cobf_error::COBF_CANNOT_REMOVE_DBG_SYMS:strcpy_s(buffer, size, "Cannot remove the symbols table."); break;
	case cobf_error::COBF_MODULE_NOT_FOUND:      strcpy_s(buffer, size, "The module was not found."); break;
	case cobf_error::COBF_PE_LOADED:             strcpy_s(buffer, size, "The PE is already loaded."); break;
	case cobf_error::COBF_PE_UNLOADED:           strcpy_s(buffer, size, "The PE is already unloaded."); break;
	case cobf_error::COBF_SYMS_NOT_FOUND:        strcpy_s(buffer, size, "The symbol(s) couldn't be found."); break;
	default:									 strcpy_s(buffer, size, "Unknown error code."); break;
	}
};

#endif // !UTILS_CPP.