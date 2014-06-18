#ifndef _ASM_H8300_MODULE_H
#define _ASM_H8300_MODULE_H
/*
 * This file contains the H8/300 architecture specific module code.
 */
struct mod_arch_specific { };
#define MODULES_ARE_ELF32
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define ELF_R_TYPE(X)	ELF32_R_TYPE(X)
#define ELF_R_SYM(X)	ELF32_R_SYM(X)

#define MODULE_SYMBOL_PREFIX "_"

#endif /* _ASM_H8/300_MODULE_H */
