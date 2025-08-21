// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>
#include <stdlib.h>
#include <objtool/special.h>
#include <objtool/builtin.h>
#include <objtool/warn.h>
#include <asm/byteorder.h>
#include <errno.h>


struct section *ftr_alt;

//struct section *ftr_alt;

struct fixup_entry *fes;
unsigned int nr_fes;

uint64_t fe_alt_start = -1;
uint64_t fe_alt_end;



bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct reloc *reloc)
{
	exit(-1);
}

struct reloc *arch_find_switch_table(struct objtool_file *file,
				     struct instruction *insn,
				     unsigned long *table_size)
{
	exit(-1);
}

int process_alt_data(struct objtool_file *file)
{
        struct section *section;
                 
        section = find_section_by_name(file->elf, ".__ftr_alternates.text");
        ftr_alt = section;

        if (!ftr_alt) { 
                WARN(".__ftr_alternates.text section not found\n");
                return -1;
        }

        printf("found section: %s\n", section->name);
        return 0;
}

static int is_le(struct objtool_file *file)
{
    return file->elf->ehdr.e_ident[EI_DATA] == ELFDATA2LSB;
}

static int is_64bit(struct objtool_file *file)
{
    return file->elf->ehdr.e_ident[EI_CLASS] == ELFCLASS64;
}

static uint32_t f32_to_cpu(struct objtool_file *file, uint32_t val)
{
    if (is_le(file)) {
	printf("32 bit LE\n");
        return __le32_to_cpu(val);
	}
    else {
	printf("32 bit BE\n");
        return __be32_to_cpu(val);
	}
}

static uint64_t f64_to_cpu(struct objtool_file *file, uint64_t val)
{
    if (is_le(file))
        return __le64_to_cpu(val);
    else
        return __be64_to_cpu(val);
}
/*
int process_fixup_entries(struct objtool_file *file)
{
        struct section *sec;
        unsigned int nr = 0;
        int i;

        for_each_sec(file, sec) {
                if (strstr(sec->name, "_ftr_fixup") != NULL) {
                        Elf_Data *data = sec->data;

                      printf("processing section: %s\n", sec->name);
                        if (data && data->d_size > 0) {
                                nr = data->d_size / sizeof(struct fixup_entry_64);

                                for (i = 0; i < nr; i++) {

                                        unsigned long idx;
                                        unsigned long long off;
                                        struct fixup_entry_64 *dst;

                                        if (is_64bit(file)) {
                                                struct fixup_entry_64 *src;
                                                //struct fixup_entry_64 *dst;

                                              printf("is 64 bit\n");
                                                idx = i * sizeof(struct fixup_entry_64);
                                                off = sec->sh.sh_addr + data->d_off + idx;
                                                src = data->d_buf + idx;

                                                if (src->alt_start_off == src->alt_end_off)
                                                        continue;

                                                fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
                                                dst = &fes[nr_fes];
                                                nr_fes++;

                                                dst->mask = f64_to_cpu(file, src->mask);
                                                dst->value = f64_to_cpu(file, src->value);
                                                dst->start_off = f64_to_cpu(file, src->start_off) + off;
                                                dst->end_off = f64_to_cpu(file, src->end_off) + off;
                                                dst->alt_start_off = f64_to_cpu(file, src->alt_start_off) + off;
                                                dst->alt_end_off = f64_to_cpu(file, src->alt_end_off) + off;
                                                printf("off: 0x%llx\n", off);
						printf("src->start_off: 0x%lx, src->end_off: 0x%lx\n", src->start_off, src->end_off);
						printf("dst->start_off: 0x%lx, dst->end_off: 0x%lx\n", dst->start_off, dst->end_off);
                                                printf("src->alt_start_off: 0x%lx, src->alt_end_off: 0x%lx\n", src->alt_start_off, src->alt_end_off);
                                                printf("dst->alt_start_off: 0x%lx, dst->alt_end_off: 0x%lx\n", dst->alt_start_off, dst->alt_end_off);
                                                printf("fe_alt_start: 0x%lx, fe_alt_end: 0x%lx\n", fe_alt_start, fe_alt_end);

                                        }

                                        else {
                                                struct fixup_entry_32 *src;
                                                //struct fixup_entry_64 *dst;

//                                              printf("is 32 bit\n");

                                                idx = i * sizeof(struct fixup_entry_32);

                                                off = sec->sh.sh_addr + data->d_off + idx;
                                                src = data->d_buf + idx;

                                                if (src->alt_start_off == src->alt_end_off)
                                                        continue;

                                                fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
                                                dst = &fes[nr_fes];
                                                nr_fes++;

                                                dst->mask = f32_to_cpu(file, src->mask);
                                                dst->value = f32_to_cpu(file, src->value);
                                                dst->start_off = (int32_t)f32_to_cpu(file, src->start_off) + off;
                                                dst->end_off = (int32_t)f32_to_cpu(file, src->end_off) + off;
                                                dst->alt_start_off = (int32_t)f32_to_cpu(file, src->alt_start_off) + off;
                                                dst->end_off = (int32_t)f32_to_cpu(file, src->end_off) + off;
                                                dst->alt_start_off = (int32_t)f32_to_cpu(file, src->alt_start_off) + off;
                                                dst->alt_end_off = (int32_t)f32_to_cpu(file, src->alt_end_off) + off;

                                                printf("off: 0x%llx\n", off);
                                                printf("src->alt_start_off: 0x%x, src->alt_end_off: 0x%x\n", src->alt_start_off, src->alt_end_off);
                                                printf("f32_to_cpu(file, src->alt_start_off): 0x%x, f32_to_cpu(file, src->alt_end_off): 0x%x\n", f32_to_cpu(file, src->alt_start_off), f32_to_cpu(file, src->alt_end_off));
                                                printf("dst->start_off: 0x%lx, dst->end_off: 0x%lx\n", dst->start_off, dst->end_off);
                                        printf("dst->alt_start_off: 0x%lx, dst->alt_end_off: 0x%lx\n", dst->alt_start_off, dst->alt_end_off);
                                                printf("fe_alt_start: 0x%lx, fe_alt_end: 0x%lx\n", fe_alt_start, fe_alt_end);
                                        }

                                        if (strstr(sec->name, ".rela") == NULL) {
                                                if (dst->alt_start_off < fe_alt_start)
                                                        fe_alt_start = dst->alt_start_off;

                                                if (dst->alt_end_off > fe_alt_end)
                                                        fe_alt_end = dst->alt_end_off;
                                        }


//                                      printf("%llx fixup entry %llx:%llx (%llx-%llx) <- (%llx-%llx)\n", off,
//                                      (unsigned long long)dst->mask, (unsigned long long)dst->value,
//                                      (unsigned long long)dst->start_off, (unsigned long long)dst->end_off,
//                                      (unsigned long long)dst->alt_start_off, (unsigned long long)dst->alt_end_off);
                                }
                        }
                }
        }

        return 0;
}
*/


// Fix 1: Add the missing cpu_to_f32 function (place this with other helper functions)
static uint32_t cpu_to_f32(struct objtool_file *file, uint32_t val)
{
        if (is_le(file))
                return __cpu_to_le32(val);
        else
                return __cpu_to_be32(val);
}

// Fix 2: Replace process_fixup_entries with C90 compliant version
int process_fixup_entries(struct objtool_file *file)
{
        struct section *sec;
        int i;
        
        for_each_sec(file, sec) {
                Elf_Data *data;
                unsigned int nr;
                
                if (strstr(sec->name, "_ftr_fixup") == NULL)
                        continue;
                        
                if (strstr(sec->name, ".rela") != NULL)
                        continue;
                
                data = sec->data;
                if (!data || data->d_size == 0)
                        continue;
                        
                printf("processing section: %s\n", sec->name);
                
                if (is_64bit(file)) {
                        nr = data->d_size / sizeof(struct fixup_entry_64);
                } else {
                        nr = data->d_size / sizeof(struct fixup_entry_32);
                }
                
                for (i = 0; i < nr; i++) {
                        unsigned long idx;
                        unsigned long long off;
                        struct fixup_entry_64 *dst;
                        
                        if (is_64bit(file)) {
                                struct fixup_entry_64 *src;
                                printf("is 64 bit\n");
                                idx = i * sizeof(struct fixup_entry_64);
                                off = sec->sh.sh_addr + data->d_off + idx;
                                src = data->d_buf + idx;
                                
                                if (src->alt_start_off == src->alt_end_off)
                                        continue;
                                        
                                fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
                                dst = &fes[nr_fes];
                                nr_fes++;
                                
                                dst->mask = f64_to_cpu(file, src->mask);
                                dst->value = f64_to_cpu(file, src->value);
                                dst->start_off = f64_to_cpu(file, src->start_off) + off;
                                dst->end_off = f64_to_cpu(file, src->end_off) + off;
                                dst->alt_start_off = f64_to_cpu(file, src->alt_start_off) + off;
                                dst->alt_end_off = f64_to_cpu(file, src->alt_end_off) + off;
				printf("src->start_off: 0x%lx, src->end_off: 0x%lx\n", src->start_off, src->end_off);
				printf("off: 0x%llx\n", off);
				printf("dst->start_off: 0x%lx, dst->end_off: 0x%lx\n", dst->start_off, dst->end_off);
                        }
                        else {
                                struct fixup_entry_32 *src;
				printf("is 32 bit\n");
                                idx = i * sizeof(struct fixup_entry_32);
                                off = sec->sh.sh_addr + data->d_off + idx;
                                src = data->d_buf + idx;
                                
                                if (src->alt_start_off == src->alt_end_off)
                                        continue;
                                        
                                fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
                                dst = &fes[nr_fes];
                                nr_fes++;
                                
                                dst->mask = f32_to_cpu(file, src->mask);
                                dst->value = f32_to_cpu(file, src->value);
                                dst->start_off = (int32_t)f32_to_cpu(file, src->start_off) + off;
                                dst->end_off = (int32_t)f32_to_cpu(file, src->end_off) + off;
                                dst->alt_start_off = (int32_t)f32_to_cpu(file, src->alt_start_off) + off;
                                dst->alt_end_off = (int32_t)f32_to_cpu(file, src->alt_end_off) + off;
                        }
                        
                        if (dst->alt_start_off < fe_alt_start)
                                fe_alt_start = dst->alt_start_off;
                        if (dst->alt_end_off > fe_alt_end)
                                fe_alt_end = dst->alt_end_off;
                                
                        printf("off: 0x%llx\n", off);
                        printf("dst->start_off: 0x%lx, dst->end_off: 0x%lx\n", dst->start_off, dst->end_off);
                        printf("dst->alt_start_off: 0x%lx, dst->alt_end_off: 0x%lx\n", dst->alt_start_off, dst->alt_end_off);
                        printf("fe_alt_start: 0x%lx, fe_alt_end: 0x%lx\n", fe_alt_start, fe_alt_end);
                }
        }
        return 0;
}

struct fixup_entry *find_fe_altaddr(uint64_t addr)
{
        unsigned int i;

        if (addr < fe_alt_start)
                return NULL;
        if (addr >= fe_alt_end)
                return NULL;

        for (i = 0; i < nr_fes; i++) {
                if (addr >= fes[i].alt_start_off && addr < fes[i].alt_end_off)
                        return &fes[i];
        }
        return NULL;
}

int set_uncond_branch_target(uint32_t *insn,
               const uint64_t addr, uint64_t target)
{
        uint32_t i = *insn;
        int64_t offset;

        offset = target;
        if (!(i & BRANCH_ABSOLUTE))
                offset = offset - addr;

        /* Check we can represent the target in the instruction format */
        if (offset < -0x2000000 || offset > 0x1fffffc || offset & 0x3)
                return -EOVERFLOW;

        /* Mask out the flags and target, so they don't step on each other. */
        *insn = 0x48000000 | (i & 0x3) | (offset & 0x03FFFFFC);

        return 0;
}
int set_cond_branch_target(uint32_t *insn,
               const uint64_t addr, uint64_t target)
{
        uint32_t i = *insn;
        int64_t offset;

        offset = target;

        if (!(i & BRANCH_ABSOLUTE))
                offset = offset - addr;

        /* Check we can represent the target in the instruction format */
        if (offset < -0x8000 || offset > 0x7FFF || offset & 0x3) {
                printf("cannot represent\n");
                return -EOVERFLOW;
        }

        /* Mask out the flags and target, so they don't step on each other. */
        *insn = 0x40000000 | (i & 0x3FF0003) | (offset & 0xFFFC);

        return 0;
}

void check_and_flatten_fixup_entries(void)
{
        static struct fixup_entry *fe;
        unsigned int i;

        i = nr_fes;
        while (i) {
                static struct fixup_entry *parent;
                uint64_t nested_off; /* offset from start of parent */
                uint64_t size;

                i--;
                fe = &fes[i];

                parent = find_fe_altaddr(fe->start_off);
                if (!parent) {
                        parent = find_fe_altaddr(fe->end_off);
                        continue;
                }

                size = fe->end_off - fe->start_off;
                nested_off = fe->start_off - parent->alt_start_off;

                fe->start_off = parent->start_off + nested_off;
                fe->end_off = fe->start_off + size;
        }
}
/*
int process_bug_entries(struct objtool_file *file)
{
        struct section *section;

        Elf_Data *data;
        unsigned int nr, i;

        section = find_section_by_name(file->elf, "__bug_table");

        data = section->data;

        if (is_64bit(file))
                nr = data->d_size / sizeof(struct bug_entry_64);
        else
                nr = data->d_size / sizeof(struct bug_entry_32);

        for (i = 0; i < nr; i++) {
                unsigned long idx;
                uint64_t bugaddr;
                unsigned long long off;

                if (is_64bit(file)) {
                        struct bug_entry_64 *bug;

//                      printf("process_bug_entries(): 64 bit\n");

                        idx = i * sizeof(struct bug_entry_64);
                        off = section->sh.sh_addr + data->d_off + idx;
                        bug = data->d_buf + idx;
                        bugaddr = (bug->bug_addr) + off;
//                      printf("bugaddr[%d]: 0x%lx\n", i, bugaddr);
//                      printf("off: 0x%llx\n", off);
//                      printf("fe_alt_start: 0x%lx\n", fe_alt_start);
//                      printf("fe_alt_end: 0x%lx\n", fe_alt_end);
                }

                else {
                        struct bug_entry_32 *bug;
                        uint32_t rel_value;

//                      printf("process_bug_entries(): 32 bit\n");

                        idx = i * sizeof(struct bug_entry_32);
                        off = section->sh.sh_addr + data->d_off + idx;
                        bug = data->d_buf + idx;
                        rel_value = f32_to_cpu(file, bug->bug_addr);
                        bugaddr = off + (int32_t)rel_value;
                        //printf("off: 0x%llx\n", off);
                        //bugaddr += off;
                        //printf("bugaddr[%d]: 0x%lx\n", i, bugaddr);
    //                   printf("off: 0x%llx\n", off);
      //                  printf("fe_alt_start: 0x%lx\n", fe_alt_start);
        //                printf("fe_alt_end: 0x%lx\n", fe_alt_end);

                }


                printf("bugaddr[%d]: 0x%lx\n", i, bugaddr);
                printf("off: 0x%llx\n", off);
                printf("bugaddr[%d] + off: 0x%llx\n", i, bugaddr + off);
                printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                printf("fe_alt_end: 0x%lx\n", fe_alt_end);


                if (bugaddr < fe_alt_start)
                        continue;

                if (bugaddr >= fe_alt_end)
                        continue;

                printf("bug_entries: hitting EXIT_FAILURE\n");

                printf("bug_entries: hitting EXIT_FAILURE\n");
                printf("ftr_alt code contains a bug entry, which is not allowed. address=%llx\n", (unsigned long long)bugaddr);
                exit(EXIT_FAILURE);
        }

        return 0;
}
*/

static struct symbol *find_symbol_at_address_within_section(struct section *sec,
                                                                unsigned long address)
{
        struct symbol *sym;

        sec_for_each_sym(sec, sym) {
                if (sym->sym.st_value <= address && address < sym->sym.st_value + sym->len)
                        return sym;
        }

        return NULL;
}

static int is_local_symbol(uint8_t st_other)
{
        return (st_other & 0x3) != 0;
}

static struct symbol *find_symbol_at_address(struct objtool_file *file,
                                                unsigned long address)
{
        struct section *sec;
        struct symbol *sym;

        list_for_each_entry(sec, &file->elf->sections, list) {
                sym = find_symbol_at_address_within_section(sec, address);
                if (sym)
                        return sym;
        }
        return NULL;
}

/*
int process_alt_relocations(struct objtool_file *file)
{
        struct section *section;
        size_t n = 0;
        uint32_t insn;
        uint32_t *i;
        unsigned int opcode;
        struct reloc *relocation;
        struct symbol *sym;
        struct fixup_entry *fe;
        uint64_t addr;
        uint64_t scn_delta;
        uint64_t dst_addr;
        const char *insn_ptr;
        unsigned long target;
        struct symbol *symbol;
        int is_local;
        int j;

        section = find_section_by_name(file->elf, ".rela.__ftr_alternates.text");
        if (!section) {
                printf(".rela.__ftr_alternates.text section not found.\n");
                return -1;
        }
        printf(".rela.__ftr_alternates.text section found.\n");
        printf("Number of entries in section: %d\n", sec_num_entries(section));

        for (j = 0; j < sec_num_entries(section); j++) {
                printf("\nProcessing entry %d\n", j);
                relocation = &section->relocs[j];
                sym = relocation->sym;
                addr = reloc_offset(relocation);
                printf("Relocation address: 0x%lx\n", addr);

                target = sym->sym.st_value + reloc_addend(relocation);
                printf("Initial target: 0x%lx\n", target);

                symbol = find_symbol_at_address(file, target);
                if (symbol) {
                        printf("Symbol found at target address\n");
                        is_local = is_local_symbol(symbol->sym.st_other);
                        if (!is_local) {
                                target = target + 0x8;
                                printf("Non-local symbol, adjusted target: 0x%lx\n", target);
                        }
                }
                n++;

                fe = find_fe_altaddr(addr);
                if (!fe) {
                        printf("No fixup entry found for address 0x%lx\n", addr);
                        continue;
                }

                printf("Fixup entry found, checking target ranges\n");
                if (target >= fe->alt_start_off && target < fe->alt_end_off) {
                        printf("alt_start_off: 0x%x\n", (int32_t) fe->alt_start_off);
                        printf("alt_end_off: 0x%x\n", (int32_t) fe->alt_end_off);
                        printf("Target within alt range, skipping\n");
                        continue;
                }

                        printf("alt_start_off: 0x%x\n", f32_to_cpu(file, (int32_t) fe->alt_start_off));
                        printf("alt_end_off: 0x%x\n", f32_to_cpu(file, (int32_t) fe->alt_end_off));


                if (target >= ftr_alt->sh.sh_addr &&
                    target < ftr_alt->sh.sh_addr + ftr_alt->sh.sh_size) {
                        printf("ftr_alt branch target is another ftr_alt region.\n");
                        exit(EXIT_FAILURE);
                }


                scn_delta = addr - ftr_alt->sh.sh_addr;
                dst_addr = addr - fe->alt_start_off + fe->start_off;
                printf("Calculated values:\n");
                printf("scn_delta: 0x%lx\n", scn_delta);
                printf("dst_addr: 0x%lx\n", dst_addr);
                printf("target: 0x%lx\n", target);

                i = ftr_alt->data->d_buf + scn_delta;
                if (!i || !ftr_alt->data->d_buf) {
                        printf("Error: Invalid buffer pointer\n");
                        continue;
                }

                insn = f32_to_cpu(file, *i);
                printf("Instruction before modification: 0x%x\n", insn);

                opcode = insn >> 26;
                printf("Opcode: %u\n", opcode);

                if (opcode == 16) {
                        printf("Processing conditional branch\n");
                        set_cond_branch_target(&insn, dst_addr, target);
                }
                if (opcode == 18) {
                        printf("Processing unconditional branch\n");
                        set_uncond_branch_target(&insn, dst_addr, target);
                }

                printf("Instruction after modification: 0x%x\n", insn);
                insn_ptr = (const char *)&insn;
                elf_write_insn(file->elf, ftr_alt, scn_delta, sizeof(insn), insn_ptr);
        }
        printf("Processed %zu total entries\n", n);
        return 0;
}
*/


// Fix 3: Replace process_alt_relocations with C90 compliant version
int process_alt_relocations(struct objtool_file *file)
{
        struct section *section;
        size_t n = 0;
        uint32_t insn;
        uint32_t *i;
        unsigned int opcode;
        struct reloc *relocation;
        struct symbol *sym;
        struct fixup_entry *fe;
        uint64_t addr;
        uint64_t scn_delta;
        uint64_t dst_addr;
        const char *insn_ptr;
        unsigned long target;
        struct symbol *symbol;
        int is_local; 
        int j;
        uint32_t new_insn;
        uint32_t file_insn;
                
        section = find_section_by_name(file->elf, ".rela.__ftr_alternates.text");
        if (!section) {
                printf(".rela.__ftr_alternates.text section not found.\n");
                return -1;
        }
        
        printf(".rela.__ftr_alternates.text section found.\n");
        printf("Number of entries in section: %d\n", sec_num_entries(section));
        
        for (j = 0; j < sec_num_entries(section); j++) {
                printf("\nProcessing entry %d\n", j);
                relocation = &section->relocs[j];
                sym = relocation->sym;
                addr = reloc_offset(relocation);
                printf("Relocation address: 0x%lx\n", addr);
                
                target = sym->sym.st_value + reloc_addend(relocation);
                printf("Initial target: 0x%lx\n", target);
                
                symbol = find_symbol_at_address(file, target);
                if (symbol) {
                        printf("Symbol found at target address\n");
                        is_local = is_local_symbol(symbol->sym.st_other);
                        if (!is_local) {
                                target = target + 0x8;
                                printf("Non-local symbol, adjusted target: 0x%lx\n", target);
                        }
                }
                
                n++;
                fe = find_fe_altaddr(addr);
                if (!fe) {
                        printf("No fixup entry found for address 0x%lx\n", addr);
                        continue;
                }
                
                printf("Fixup entry found, checking target ranges\n");
                if (target >= fe->alt_start_off && target < fe->alt_end_off) {
                        printf("Target within alt range, skipping\n");
                        continue;
                }
                
                if (target >= ftr_alt->sh.sh_addr &&
                    target < ftr_alt->sh.sh_addr + ftr_alt->sh.sh_size) {
                        printf("ftr_alt branch target is another ftr_alt region.\n");
                        return -1;
                }
                
                scn_delta = addr - ftr_alt->sh.sh_addr;
                dst_addr = addr - fe->alt_start_off + fe->start_off;
                
                printf("Calculated values:\n");
                printf("scn_delta: 0x%lx\n", scn_delta);
                printf("dst_addr: 0x%lx\n", dst_addr);
                printf("target: 0x%lx\n", target);
                
                i = ftr_alt->data->d_buf + scn_delta;
                if (!i || !ftr_alt->data->d_buf) {
                        printf("Error: Invalid buffer pointer\n");
                        continue;
                }
                
                insn = f32_to_cpu(file, *i);
                printf("Instruction before modification: 0x%x\n", insn);
                
                opcode = insn >> 26;
                printf("Opcode: %u\n", opcode);
                
                new_insn = insn;
                if (opcode == 16) {
                        printf("Processing conditional branch\n");
                        if (set_cond_branch_target(&new_insn, dst_addr, target) != 0) {
                                printf("Error: Could not set conditional branch target\n");
                                continue;
                        }
                } else if (opcode == 18) {
                        printf("Processing unconditional branch\n");
                        if (set_uncond_branch_target(&new_insn, dst_addr, target) != 0) {
                                printf("Error: Could not set unconditional branch target\n");
                                continue;
                        }
                } else {
                        printf("Not a branch instruction, skipping\n");
                        continue;
                }
                
                if (new_insn == insn) {
                        printf("No change needed\n");
                        continue;
                }
                
                printf("Instruction after modification: 0x%x\n", new_insn);
                
                /* Convert back to file endianness before writing */
                file_insn = cpu_to_f32(file, new_insn);
                insn_ptr = (const char *)&file_insn;
                elf_write_insn(file->elf, ftr_alt, scn_delta, sizeof(file_insn), insn_ptr);
        }
        
        printf("Processed %zu total entries\n", n);
        return 0;
}

/*
int process_exception_entries(struct objtool_file *file)
{
        struct section *section;
        Elf_Data *data;
        unsigned int nr, i;

        section = find_section_by_name(file->elf, "__ex_table");

        data = section->data;

        if (is_64bit(file))
                nr = data->d_size / sizeof(struct exception_entry_64);
        else
                nr = data->d_size / sizeof(struct exception_entry_32);

        for (i = 0; i < nr; i++) {
                unsigned long idx;
                uint64_t exaddr;
                unsigned long long off;

                if (is_64bit(file)) {
                        struct exception_entry_64 *ex;

//                      printf("process_exception_entries(): 64 bit\n");
                        idx = i * sizeof(struct exception_entry_64);
                        off = section->sh.sh_addr + data->d_off + idx;
                        ex = data->d_buf + idx;
                        exaddr = (ex->insn) + off;
//                      printf("off: 0x%llx\n", off);
//                      printf("(ex->insn): 0x%x\n", (ex->insn));
//                      printf("exaddr[%d]: 0x%lx\n", i, exaddr);
//                      printf("fe_alt_start: 0x%lx\n", fe_alt_start);
//                      printf("fe_alt_end: 0x%lx\n", fe_alt_end);

                }
                else {
                        struct exception_entry_32 *ex;
//                      printf("process_exception_entries(): 32 bit\n");
                        idx = i * sizeof(struct exception_entry_32);
                        off = section->sh.sh_addr + data->d_off + idx;
                        ex = data->d_buf + idx;
                        exaddr = (int32_t)f32_to_cpu(file, ex->insn) + off;
//                      printf("off: 0x%llx\n", off);
//                        printf("(int32_t)f32_to_cpu(file, ex->insn): 0x%x\n",(int32_t) f32_to_cpu(file, ex->insn));
//                        printf("exaddr[%d]: 0x%lx\n", i, exaddr);
//                        printf("fe_alt_start: 0x%lx\n", fe_alt_start);
//                        printf("fe_alt_end: 0x%lx\n", fe_alt_end);
                }

                printf("off: 0x%llx\n", off);
                printf("(ex->insn): 0x%x\n", (ex->insn));
                printf("exaddr[%d]: 0x%lx\n", i, exaddr);
                printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                printf("fe_alt_end: 0x%lx\n", fe_alt_end);


                if (exaddr < fe_alt_start)
                        continue;
                if (exaddr >= fe_alt_end)
                        continue;

                printf("exception_entries: hitting EXIT_FAILURE\n");
                exit(EXIT_FAILURE);
        }

        return 0;
}
*/

// Fix 3: Replace process_exception_entries function
int process_exception_entries(struct objtool_file *file)
{
        struct section *section;
        Elf_Data *data;
        unsigned int nr, i;
        
        section = find_section_by_name(file->elf, "__ex_table");
        if (!section) {
                printf("__ex_table section not found\n");
                return 0;  // Not an error if section doesn't exist
        }
        
        data = section->data;
        if (!data || data->d_size == 0) {
                return 0;
        }
        
        if (is_64bit(file))
                nr = data->d_size / sizeof(struct exception_entry_64);
        else
                nr = data->d_size / sizeof(struct exception_entry_32);
                
        for (i = 0; i < nr; i++) {
                unsigned long idx;
                uint64_t exaddr;
                unsigned long long off;
                
                if (is_64bit(file)) {
                        struct exception_entry_64 *ex;
                        idx = i * sizeof(struct exception_entry_64);
                        off = section->sh.sh_addr + data->d_off + idx;
                        ex = data->d_buf + idx;
                        // FIXED: Both 32-bit and 64-bit use relative addressing
                        exaddr = off + (int32_t)f32_to_cpu(file, ex->insn);
                }
                else {
                        struct exception_entry_32 *ex;
                        idx = i * sizeof(struct exception_entry_32);
                        off = section->sh.sh_addr + data->d_off + idx;
                        ex = data->d_buf + idx;
                        exaddr = off + (int32_t)f32_to_cpu(file, ex->insn);
                }
                
                if (exaddr < fe_alt_start)
                        continue;
                if (exaddr >= fe_alt_end)
                        continue;
                        
                printf("exception_entries: hitting EXIT_FAILURE\n");
                printf("Exception entry in alternate section at 0x%lx\n", exaddr);
                return -1;  // Return error instead of exit
        }
        return 0;
}

// Fix 4: Replace process_bug_entries function
int process_bug_entries(struct objtool_file *file)
{
        struct section *section;
        Elf_Data *data;
        unsigned int nr, i;
        
        section = find_section_by_name(file->elf, "__bug_table");
        if (!section) {
                printf("__bug_table section not found\n");
                return 0;  // Not an error if section doesn't exist
        }
        
        data = section->data;
        if (!data || data->d_size == 0) {
                return 0;
        }
        
        if (is_64bit(file))
                nr = data->d_size / sizeof(struct bug_entry_64);
        else
                nr = data->d_size / sizeof(struct bug_entry_32);
                
        for (i = 0; i < nr; i++) {
                unsigned long idx;
                uint64_t bugaddr;
                unsigned long long off;
                
                if (is_64bit(file)) {
                        struct bug_entry_64 *bug;
                        idx = i * sizeof(struct bug_entry_64);
                        off = section->sh.sh_addr + data->d_off + idx;
                        bug = data->d_buf + idx;
                        // FIXED: 64-bit uses absolute addressing
                        bugaddr = f64_to_cpu(file, bug->bug_addr);
                }
                else {  
                        struct bug_entry_32 *bug;
                        idx = i * sizeof(struct bug_entry_32);
                        off = section->sh.sh_addr + data->d_off + idx;
                        bug = data->d_buf + idx;
                        // FIXED: 32-bit uses relative addressing
                        bugaddr = off + (int32_t)f32_to_cpu(file, bug->bug_addr);
                }
                
                if (bugaddr < fe_alt_start)
                        continue;
                if (bugaddr >= fe_alt_end)
                        continue;
                        
                printf("bug_entries: hitting EXIT_FAILURE\n");
                printf("ftr_alt code contains a bug entry, which is not allowed. address=%llx\n", 
                       (unsigned long long)bugaddr);
                return -1;  // Return error instead of exit
        }
        return 0;
}

