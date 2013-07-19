#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/file.h>

#include <linux/fs.h>
#include <linux/binfmts.h>

#include "pe.h"

static int load_pe_binary(struct linux_binprm *bprm);
static int load_pe_library(struct file *file);
static int pe_core_dump (struct coredump_params *cprm);
static int init_pe_loader(void);
static void exit_pe_loader(void);

static struct linux_binfmt pe_format_callbacks = {
	.lh = {
		.next = NULL,
		.prev = NULL
	},
	.module			= THIS_MODULE,
	.load_binary	= load_pe_binary,
	.load_shlib		= load_pe_library,
	.core_dump		= pe_core_dump,
	.min_coredump	= PE_EXEC_PAGESIZE
};

void print_coff_header(struct coff_header_t *coff_header) {
	printk(KERN_INFO "PE_LOADER: coff_header_t:\n");
	printk("    pe_signature %i\n", coff_header->pe_signature);
	printk("    machine %i\n", coff_header->machine);
	printk("    number_of_sections %i\n", coff_header->number_of_sections);
	printk("    time_date_stamp %i\n", coff_header->time_date_stamp);
	printk("    pointer_to_symbol_table %i\n", coff_header->pointer_to_symbol_table);
	printk("    number_of_symbols %i\n", coff_header->number_of_symbols);
	printk("    size_of_optional_header %i\n", coff_header->size_of_optional_header);
	printk("    characteristics %i\n", coff_header->characteristics);
}

int print_optional_header_pe32(struct coff_optional_header_pe32_t *pe32_header) {
	printk(KERN_INFO "PE_LOADER: coff_optional_header_pe32_t:\n");
	printk(KERN_INFO "    magic number %i\n", pe32_header->magic_number);
	printk(KERN_INFO "    major %i\n", pe32_header->linker_version.major);
	printk(KERN_INFO "    minor %i\n", pe32_header->linker_version.minor);
	printk(KERN_INFO "    size_of_code %i\n", pe32_header->size_of_code);
	printk(KERN_INFO "    size_of_initialized_data %i\n",
		   pe32_header->size_of_initialized_data);
	printk(KERN_INFO "    size_of_uninitialized_data %i\n",
		   pe32_header->size_of_uninitialized_data);
	printk(KERN_INFO "    size_of_entry_point %i\n",
		   pe32_header->size_of_entry_point);
	printk(KERN_INFO "    base_of_code %i\n", pe32_header->base_of_code);

	printk(KERN_INFO "    base_of_data %i\n", pe32_header->base_of_data);
	printk(KERN_INFO "    image_base %i\n", pe32_header->image_base);
	printk(KERN_INFO "    section_alignment %i\n",
		   pe32_header->section_alignment);
	printk(KERN_INFO "    file_alignment %i\n", pe32_header->file_alignment);
	printk(KERN_INFO "    os_version.major %i\n",
		   pe32_header->os_version.major);
	printk(KERN_INFO "    os_version.minor %i\n",
		   pe32_header->os_version.minor);
	printk(KERN_INFO "    image_version.major %i\n",
		   pe32_header->image_version.major);
	printk(KERN_INFO "    image_version.minor %i\n",
		   pe32_header->image_version.minor);

	printk(KERN_INFO "    subsystem_version.major %i\n",
		   pe32_header->subsystem_version.major);
	printk(KERN_INFO "    subsystem_version.minor %i\n",
		   pe32_header->subsystem_version.minor);
	printk(KERN_INFO "    win32_version_value %i\n",
		   pe32_header->win32_version_value);
	printk(KERN_INFO "    size_of_image %i\n", pe32_header->size_of_image);
	printk(KERN_INFO "    size_of_headers %i\n", pe32_header->size_of_headers);
	printk(KERN_INFO "    check_sum %i\n", pe32_header->check_sum);
	printk(KERN_INFO "    subsystem %i\n", pe32_header->subsystem);
	printk(KERN_INFO "    dll_characteristics %i\n",
		   pe32_header->dll_characteristics);

	printk(KERN_INFO "    size_of_stack.reserve %i\n",
		   pe32_header->size_of_stack.reserve);
	printk(KERN_INFO "    size_of_stack.commit %i\n",
		   pe32_header->size_of_stack.commit);
	printk(KERN_INFO "    size_of_heap.reserve %i\n",
		   pe32_header->size_of_heap.reserve);
	printk(KERN_INFO "    size_of_heap.commit %i\n",
		   pe32_header->size_of_heap.commit);
	printk(KERN_INFO "    loader_flags %i\n", pe32_header->loader_flags);
	printk(KERN_INFO "    number_of_rvas %i\n", pe32_header->number_of_rvas);

	printk(KERN_INFO "    export_table            size %u address %u\n",
		   pe32_header->entry[DIRECTORY_EXPORT_TABLE].size,
		   pe32_header->entry[DIRECTORY_EXPORT_TABLE].virtual_address);
	printk(KERN_INFO "    import_table            size %u address %u\n",
		   pe32_header->entry[DIRECTORY_IMPORT_TABLE].size,
		   pe32_header->entry[DIRECTORY_IMPORT_TABLE].virtual_address);

	printk(KERN_INFO "    resource_table          size %u address %u\n",
		   pe32_header->entry[DIRECTORY_RESOURCE_TABLE].size,
		   pe32_header->entry[DIRECTORY_RESOURCE_TABLE].virtual_address);
	printk(KERN_INFO "    exception_table         size %u address %u\n",
		   pe32_header->entry[DIRECTORY_EXCEPTION_TABLE].size,
		   pe32_header->entry[DIRECTORY_EXCEPTION_TABLE].virtual_address);
	printk(KERN_INFO "    certificate_table       size %u address %u\n",
		   pe32_header->entry[DIRECTORY_CERTIFICATE_TABLE].size,
		   pe32_header->entry[DIRECTORY_CERTIFICATE_TABLE].virtual_address);
	printk(KERN_INFO "    base_relocation_table   size %u address %u\n",
		   pe32_header->entry[DIRECTORY_BASE_RELOCATION_TABLE].size,
		   pe32_header->entry[DIRECTORY_BASE_RELOCATION_TABLE].virtual_address);
	printk(KERN_INFO "    debug                   size %u address %u\n",
		   pe32_header->entry[DIRECTORY_DEBUG].size,
		   pe32_header->entry[DIRECTORY_DEBUG].virtual_address);
	printk(KERN_INFO "    architecture            size %u address %u\n",
		   pe32_header->entry[DIRECTORY_ARCHITECTURE].size,
		   pe32_header->entry[DIRECTORY_ARCHITECTURE].virtual_address);
	printk(KERN_INFO "    global_pointer          size %u address %u\n",
		   pe32_header->entry[DIRECTORY_GLOBAL_POINTER].size,
		   pe32_header->entry[DIRECTORY_GLOBAL_POINTER].virtual_address);
	printk(KERN_INFO "    tls_table               size %u address %u\n",
		   pe32_header->entry[DIRECTORY_TLS_TABLE].size,
		   pe32_header->entry[DIRECTORY_TLS_TABLE].virtual_address);

	printk(KERN_INFO "    load_config_table       size %u address %u\n",
		   pe32_header->entry[DIRECTORY_LOAD_CONFIG_TABLE].size,
		   pe32_header->entry[DIRECTORY_LOAD_CONFIG_TABLE].virtual_address);
	printk(KERN_INFO "    bound_import            size %u address %u\n",
		   pe32_header->entry[DIRECTORY_BOUND_IMPORT].size,
		   pe32_header->entry[DIRECTORY_BOUND_IMPORT].virtual_address);
	printk(KERN_INFO "    iat                     size %u address %u\n",
		   pe32_header->entry[DIRECTORY_IAT].size,
		   pe32_header->entry[DIRECTORY_IAT].virtual_address);
	printk(KERN_INFO "    delay_import_descriptor size %u address %u\n",
		   pe32_header->entry[DIRECTORY_DELAY_IMPORT_DESCRIPTOR].size,
		   pe32_header->entry[DIRECTORY_DELAY_IMPORT_DESCRIPTOR].virtual_address);
	printk(KERN_INFO "    clr_runtime_header      size %u address %u\n",
		   pe32_header->entry[DIRECTORY_CLR_RUNTIME_HEADER].size,
		   pe32_header->entry[DIRECTORY_CLR_RUNTIME_HEADER].virtual_address);
	printk(KERN_INFO "    reserved                size %u address %u\n",
		   pe32_header->entry[DIRECTORY_RESERVED].size,
		   pe32_header->entry[DIRECTORY_RESERVED].virtual_address);

	return 0;
}

void print_section_header(struct coff_section_header_t *section_header) {
	/* it is not guaranteed the name string in the binary will be null
	 * terminated
	 */
	char name[9] = {section_header->name[0], section_header->name[1],
					section_header->name[2], section_header->name[3],
					section_header->name[4], section_header->name[5],
					section_header->name[6], section_header->name[7],
					0
				   };

	printk(KERN_INFO "    name %s\n", name);
	printk(KERN_INFO "    virtual_size %u\n", section_header->virtual_size);
	printk(KERN_INFO "    virtual_address %u\n", section_header->virtual_address);
	printk(KERN_INFO "    size_of_raw_data %u\n", section_header->size_of_raw_data);
	printk(KERN_INFO "    pointer_to_raw_data %u\n", section_header->pointer_to_raw_data);
	printk(KERN_INFO "    pointer_to_relocations %u\n", section_header->pointer_to_relocations);
	printk(KERN_INFO "    pointer_to_line_numbers %u\n", section_header->pointer_to_line_numbers);
	printk(KERN_INFO "    number_of_relocations %u\n", section_header->number_of_relocations);
	printk(KERN_INFO "    number_of_line_numbers %u\n", section_header->number_of_line_numbers);
	printk(KERN_INFO "    characteristics 0x%X\n", section_header->characteristics);
}

struct pe_loader_t {
	struct image_dos_header_t *dos_header; /* memory is not allocated for this */
	struct coff_header_t *coff_header;
	struct coff_optional_header_pe32plus_t *pe32plus;
	struct coff_optional_header_pe32_t *pe32;
	struct coff_section_header_t *section_headers;

	struct linux_binprm *bprm;
};

struct pe_loader_t *pe_loader_create(struct linux_binprm *bprm) {
	struct pe_loader_t *pe_loader = NULL;

	printk(KERN_INFO "PE_LOADER: pe_loader_create()\n");

	pe_loader = kmalloc(sizeof(struct pe_loader_t), GFP_KERNEL);
	if (pe_loader == NULL) {
		return NULL;
	}

	memset(pe_loader, 0, sizeof(struct pe_loader_t));
	pe_loader->bprm = bprm;
	return pe_loader;
}

void pe_loader_free(struct pe_loader_t *loader) {
	printk(KERN_INFO "PE_LOADER: pe_loader_free()\n");

	if (loader->section_headers != NULL)
		kfree(loader->section_headers);
	if (loader->pe32 != NULL)
		kfree(loader->pe32);
	if (loader->pe32plus != NULL)
		kfree(loader->pe32plus);
	if (loader->coff_header != NULL)
		kfree(loader->coff_header);
}

uint32_t pe_load_dos_header(struct pe_loader_t *loader) {
	printk(KERN_INFO "PE_LOADER: pe_load_dos_header()\n");

	loader->dos_header = (struct image_dos_header_t *)loader->bprm->buf;

	if (!pe_dos_header_valid(loader->dos_header)) {
		printk(KERN_INFO "PE_LOADER: could not find dos header\n");
		return ENOEXEC;
	}

	return 0;
}

uint32_t pe_load_coff_header(struct pe_loader_t *loader) {
	uint32_t pe_header_fp = 0;
	uint32_t status = 0;

	printk(KERN_INFO "PE_LOADER: pe_load_coff_header()\n");

	pe_header_fp = pe_get_header_fp(loader->dos_header);
	loader->coff_header = kmalloc(sizeof(struct coff_header_t), GFP_KERNEL);
	if (loader->coff_header == NULL) {
		printk(KERN_ERR "PE_LOADER: error: could not allocate memory for coff header\n");
		return ENOMEM;
	}

	printk(KERN_INFO "PE_LOADER: coff header offset 0x%X\n", pe_header_fp);
	status = kernel_read(loader->bprm->file, pe_header_fp, (void *)loader->coff_header,
						 sizeof(struct coff_header_t));
	if (status != sizeof(struct coff_header_t)) {
		printk(KERN_ERR "PE_LOADER: error: could not read executable, status %i\n", status);
		return ENOEXEC;
	}

	/* check the coff header */
	if (!pe_coff_header_valid(loader->coff_header)) {
		printk(KERN_ERR "PE_LOADER: error: cout not find pe signature\n");
		return ENOEXEC;
	}

	// check architecture
	printk(KERN_INFO "PE_LOADER: machine type 0x%X\n", loader->coff_header->machine);
	if (loader->coff_header->machine != IMAGE_FILE_MACHINE_AMD64 &&
			loader->coff_header->machine != IMAGE_FILE_MACHINE_I386) {
		printk(KERN_ERR "PE_LOADER: error: executable is not i386 or amd64\n");
		return ENOEXEC;
	}

	/* parse the optional header */
	printk(KERN_INFO "PE_LOADER: size optional header 0x%X\n",
		   loader->coff_header->size_of_optional_header);
	if (loader->coff_header->size_of_optional_header == 0) {
		/* user is trying to launch an object file. */
		return ENOEXEC;
	}

	print_coff_header(loader->coff_header);
	return 0;
}

uint32_t pe_load_coff_optional_header(struct pe_loader_t *loader) {
	struct coff_optional_header_pe32_t *pe32 = NULL;
	uint32_t pe_optional_header_fp = 0;
	uint32_t status = 0;

	printk(KERN_INFO "PE_LOADER: pe_load_coff_optional_header()\n");

	/* allocate memory for the optional header */
	pe32 = kmalloc(loader->coff_header->size_of_optional_header, GFP_KERNEL);
	if (pe32 == NULL) {
		return ENOMEM;
	}
	pe_optional_header_fp = pe_get_optional_header_fp(loader->dos_header);
	printk(KERN_INFO "PE_LOADER: pe_optional_header_fp = 0x%X\n", pe_optional_header_fp);

	/* read the optional header */
	status = kernel_read(loader->bprm->file, pe_optional_header_fp,
						 (void *)pe32, loader->coff_header->size_of_optional_header);
	if (status != loader->coff_header->size_of_optional_header) {
		printk(KERN_ERR "PE_LOADER: error: could not read optional header, status %i\n", status);
		kfree(pe32);
		return ENOEXEC;
	}

	if (pe32->magic_number == IMAGE_OPTIONAL_MAGIC_EXE) {
		loader->pe32 = pe32;
		print_optional_header_pe32(loader->pe32);
	} else if (pe32->magic_number == IMAGE_OPTIONAL_MAGIC_PE32PLUS_EXE) {
		loader->pe32plus = (struct coff_optional_header_pe32plus_t *)pe32;
	} else {
		return ENOEXEC;
	}

	return 0;
}

uint32_t pe_load_section_headers(struct pe_loader_t *loader) {
	uint32_t section_headers_size = 0;
	uint32_t pe_section_headers_fp = 0;
	uint32_t status = 0;
	uint32_t i = 0;

	printk(KERN_INFO "PE_LOADER: pe_load_section_headers()\n");

	if (loader->pe32 != NULL) {
		/* get the section headers */
		section_headers_size = sizeof(struct coff_section_header_t)*
				loader->coff_header->number_of_sections;
		loader->section_headers = kmalloc(section_headers_size, GFP_KERNEL);
		if (loader->section_headers == NULL) {
			printk(KERN_ERR "PE_LOADER: error: could not allocate memory for section header");
			return ENOMEM;
		}
		pe_section_headers_fp = pe_get_section_header_fp(loader->dos_header, loader->coff_header);
		status = kernel_read(loader->bprm->file, pe_section_headers_fp,
							 (void *)loader->section_headers, section_headers_size);
		if (status != section_headers_size) {
			printk(KERN_ERR "PE_LOADER: error: could not read section headers, status %i\n", status);
			return ENOEXEC;
		}

		printk(KERN_INFO "PE_LOADER: section headers\n");
		for (i = 0; i < loader->coff_header->number_of_sections; i++) {
			print_section_header(&loader->section_headers[i]);
		}
	} else if (loader->pe32plus != NULL) {

	} else {
		printk(KERN_ERR "PE_LOADER: error: pe32 and pe32plus data members are both null\n");
	}


	return 0;
}

int load_pe_binary(struct linux_binprm *bprm) {
	struct pe_loader_t *pe_loader = NULL;
	uint32_t status = 0;

	pe_loader = pe_loader_create(bprm);
	if (pe_loader == NULL) {
		return ENOMEM;
	}

	status = pe_load_dos_header(pe_loader);
	if (status != 0) {
		pe_loader_free(pe_loader);
		return status;
	}

	status = pe_load_coff_header(pe_loader);
	if (status != 0) {
		pe_loader_free(pe_loader);
		return status;
	}

	status = pe_load_coff_optional_header(pe_loader);
	if (status != 0) {
		pe_loader_free(pe_loader);
		return status;
	}

	status = pe_load_section_headers(pe_loader);
	if (status != 0) {
		pe_loader_free(pe_loader);
		return status;
	}

	pe_loader_free(pe_loader);
    return 0;
}

int load_pe_library(struct file *file) {
	printk(KERN_INFO "**************************************************\n"
		   "PE_LOADER: load library\n"
		   "**************************************************\n");
	
	return 0;
}

int pe_core_dump(struct coredump_params *cprm) {
	printk(KERN_INFO "**************************************************\n"
		   "PE_LOADER: core dump\n"
		   "**************************************************\n");
	
	return 0;
}

int init_pe_loader(void) {
	printk(KERN_INFO "**************************************************\n"
		   "PE_LOADER: init\n"
		   "**************************************************\n");
	register_binfmt(&pe_format_callbacks);
	return 0;
}

void exit_pe_loader(void) {
	printk(KERN_INFO "**************************************************\n"
		   "PE_LOADER: exit\n"
		   "**************************************************\n");
	unregister_binfmt(&pe_format_callbacks);
}

core_initcall(init_pe_loader);
module_exit(exit_pe_loader);

MODULE_LICENSE("Public Domain");
MODULE_AUTHOR("Michael F. Varga");
MODULE_DESCRIPTION("A loader for Portable Executable formatted applications.");
