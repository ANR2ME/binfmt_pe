#include "pe.h"

uint32_t pe_get_optional_header_fp(struct image_dos_header_t *dos_header) {
	return dos_header->e_lfanew + sizeof(struct coff_header_t);
}

uint32_t pe_get_header_fp(struct image_dos_header_t *dos_header) {
	return dos_header->e_lfanew;
}

uint32_t pe_dos_header_valid(struct image_dos_header_t *dos_header) {
	return dos_header->e_magic == DOS_MAGIC_NUMBER;
}

uint32_t pe_coff_header_valid(struct coff_header_t *coff_header) {
	return coff_header->pe_signature == PE_SIGNATURE;
}

uint32_t pe_get_section_header_fp(struct image_dos_header_t *dos_header,
								  struct coff_header_t *coff_header) {
	return pe_get_optional_header_fp(dos_header) +
			coff_header->size_of_optional_header;
}
