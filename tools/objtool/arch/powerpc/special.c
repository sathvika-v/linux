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

    // Get section boundaries directly from the section
    fe_alt_start = ftr_alt->sh.sh_addr;
    fe_alt_end = ftr_alt->sh.sh_addr + ftr_alt->sh.sh_size;
    
    printf("found section: %s\n", section->name);
    printf("section range: 0x%lx - 0x%lx\n", fe_alt_start, fe_alt_end);
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


static uint32_t cpu_to_f32(struct objtool_file *file, uint32_t val)
{
        if (is_le(file))
                return __cpu_to_le32(val);
        else
                return __cpu_to_be32(val);
}


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
		printf("nr: %d\n", nr);
        } else {
            nr = data->d_size / sizeof(struct fixup_entry_32);
        }

        for (i = 0; i < nr; i++) {
            unsigned long idx;
            unsigned long long off;
            struct fixup_entry *dst;

            if (is_64bit(file)) {
                struct fixup_entry_64 *src;
                printf("is 64 bit\n");
                idx = i * sizeof(struct fixup_entry_64);
		printf("idx: %ld .... i: %d\n", idx, i);
		//off = sec->sh.sh_addr + data->d_off;
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
printf("Raw values from ELF:\n");
printf("src->mask: 0x%x\n", src->mask);                    // 0x1
printf("src->value: 0x%x\n", src->value);                  // 0x0
printf("src->start_off: 0x%x\n", src->start_off);          // 0xbcc83fff
printf("src->end_off: 0x%x\n", src->end_off);              // 0xc0c83fff
printf("src->alt_start_off: 0x%x\n", src->alt_start_off);  // 0x6441f2ff
printf("src->alt_end_off: 0x%x\n", src->alt_end_off);      // 0x6841f2ff
printf("off: 0x%llx\n", off);                              // 0xc0c0eec0
//                printf("src->start_off: 0x%x, src->end_off: 0x%x\n", src->start_off, src->end_off);
//                printf("off: 0x%llx\n", off);
//                printf("dst->start_off: 0x%lx, dst->end_off: 0x%lx\n", dst->start_off, dst->end_off);
            }

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


int process_alt_relocations(struct objtool_file *file)
{
    struct section *section;
    size_t n = 0;
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
    struct instruction decoded_insn = {0}; /* For arch_decode_instruction */
    uint32_t *insn_ptr_raw;  /* MOVED: was declared at line 824 */
    uint32_t insn;           /* MOVED: was declared at line 830 */

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

        /* Use arch_decode_instruction instead of manual decoding */
        if (arch_decode_instruction(file, ftr_alt, scn_delta, 4, &decoded_insn) < 0) {
            printf("Error: Failed to decode instruction at offset 0x%lx\n", scn_delta);
            continue;
        }

        printf("Decoded instruction type: %d\n", decoded_insn.type);
        printf("Instruction immediate: 0x%lx\n", decoded_insn.immediate);

        /* Get the raw instruction for modification */
        insn_ptr_raw = (uint32_t *)(ftr_alt->data->d_buf + scn_delta);
        if (!insn_ptr_raw || !ftr_alt->data->d_buf) {
            printf("Error: Invalid buffer pointer\n");
            continue;
        }

        insn = f32_to_cpu(file, *insn_ptr_raw);
        printf("Instruction before modification: 0x%x\n", insn);

        new_insn = insn;

        /* Use the decoded instruction type instead of manual opcode checking */
        switch (decoded_insn.type) {
        case INSN_JUMP_CONDITIONAL:
            printf("Processing conditional branch (decoded)\n");
            if (set_cond_branch_target(&new_insn, dst_addr, target) != 0) {
                printf("Error: Could not set conditional branch target\n");
                continue;
            }
            break;

        case INSN_JUMP_UNCONDITIONAL:
            printf("Processing unconditional branch (decoded)\n");
            if (set_uncond_branch_target(&new_insn, dst_addr, target) != 0) {
                printf("Error: Could not set unconditional branch target\n");
                continue;
            }
            break;

        case INSN_CALL:
            printf("Processing call instruction (decoded)\n");
            if (set_uncond_branch_target(&new_insn, dst_addr, target) != 0) {
                printf("Error: Could not set call target\n");
                continue;
            }
            break;

        default:
            printf("Not a branch/call instruction (type=%d), skipping\n", decoded_insn.type);
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
			printf("f32_to_cpu(file, ex->insn): 0x%x\n", f32_to_cpu(file, ex->insn));
			printf("(int32_t)f32_to_cpu(file, ex->insn): 0x%x\n", (int32_t)f32_to_cpu(file, ex->insn));
			printf("off: 0x%llx\n", off);
                        exaddr = off + (int32_t)f32_to_cpu(file, ex->insn);
			printf("exaddr: 0x%lx\n", exaddr);
                }
                else {
                        struct exception_entry_32 *ex;
                        idx = i * sizeof(struct exception_entry_32);
                        off = section->sh.sh_addr + data->d_off + idx;
                        ex = data->d_buf + idx;
                        exaddr = off + (int32_t)f32_to_cpu(file, ex->insn);
                        printf("f32_to_cpu(file, ex->insn): 0x%x\n", f32_to_cpu(file, ex->insn));
                        printf("(int32_t)f32_to_cpu(file, ex->insn): 0x%x\n", (int32_t)f32_to_cpu(file, ex->insn));
                        printf("off: 0x%llx\n", off);
                        exaddr = off + (int32_t)f32_to_cpu(file, ex->insn);
                        printf("exaddr: 0x%lx\n", exaddr);
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
/*
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
			printf("off: 0x%llx\n", off);
                        bugaddr = f64_to_cpu(file, bug->bug_addr);
			printf("bugaddr: 0x%lx\n", bugaddr);
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
*/

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
        printf("Empty __bug_table section\n");
        return 0;
    }
    printf("Found __bug_table section at 0x%llx, size: %zu bytes\n",
           (unsigned long long)section->sh.sh_addr, data->d_size);
    // Validate section size alignment
    if (data->d_size % sizeof(struct bug_entry) != 0) {
        printf("Error: Bug table size (%zu) not aligned to entry size (%zu)\n",
               data->d_size, sizeof(struct bug_entry));
        return -1;
    }
    nr = data->d_size / sizeof(struct bug_entry);
    printf("Processing %u bug entries (12 bytes each)\n", nr);
    for (i = 0; i < nr; i++) {
        struct bug_entry *bug;
        unsigned long idx;
        uint64_t entry_addr;
        uint64_t bugaddr;
        int32_t bug_disp;
        // Calculate entry position
        idx = i * sizeof(struct bug_entry);
        entry_addr = section->sh.sh_addr + data->d_off + idx;
        bug = (struct bug_entry *)(data->d_buf + idx);
        bug_disp = f32_to_cpu(file, bug->bug_addr_disp);
        bugaddr = entry_addr + bug_disp;

        printf("\n=== Bug Entry %u at 0x%lx ===\n", i, entry_addr);
        printf("Raw bug_addr_disp: 0x%08x\n", bug->bug_addr_disp);
        printf("Converted bug_disp: 0x%08x (%d)\n", bug_disp, bug_disp);
        printf("Bug address: 0x%lx\n", bugaddr);
        // Check if bug address is in feature alternative section
        if (bugaddr < fe_alt_start)
            continue;
        if (bugaddr >= fe_alt_end)
            continue;
        return -1;
    }
    printf("\nSuccessfully processed %u bug entries\n", nr);
    return 0;
}
