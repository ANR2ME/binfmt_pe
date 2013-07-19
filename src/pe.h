#ifndef PE_H
#define PE_H

#include "pe_types.h"

#define PE_EXEC_PAGESIZE 4096

/* TERMS:
 *	pe = portable executable - the executable format this module is responsible
 *		for parsing
 *	fp = file pointer - the offset from the beginning of the file where some
 *		important data is located
 *
 *
 */

/**
 *
 */
uint32_t pe_get_optional_header_fp(struct image_dos_header_t *dos_header);

uint32_t pe_get_header_fp(struct image_dos_header_t *dos_header);

uint32_t pe_get_section_header_fp(struct image_dos_header_t *dos_header,
								  struct coff_header_t *coff_header);

/**
 * check the struct image_dos_header_t to ensure it is pointing to a valid
 * instance.
 *
 * @return 1 if the executable file contains a valid dos header. 0 this
 *	is not a valid dos executable.
 */
uint32_t pe_dos_header_valid(struct image_dos_header_t *dos_header);

/**
 * check the struct coff_header_t to ensure it is pointing to a valid instance.
 *
 * @return 1 if the correct magic number is found in the coff_header. 0 if the
 *	correct magic number is not found.
 */
uint32_t pe_coff_header_valid(struct coff_header_t *coff_header);

#endif // PE_H
