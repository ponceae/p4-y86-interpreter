/*
 * CS 261: Main driver
 *
 * Name: Adrien Ponce
 */

#include "p1-check.h"
#include "p2-load.h"
#include "p3-disas.h"
#include "p4-interp.h"

#define PHDR_SIZE 20

int main (int argc, char **argv)
{
    bool print_header = false;
    bool print_segments = false;
    bool print_membrief = false;
    bool print_memfull = false;
    bool disas_code = false;
    bool disas_data = false;
    bool exec_normal = false;
    bool exec_trace = false;
    char *filename;

    // grab contents of command line
    if (!parse_command_line_p4(argc, argv, &print_header, &print_segments,
                               &print_membrief, &print_memfull, &disas_code,
                               &disas_data, &exec_normal, &exec_trace, &filename)) {
        exit(EXIT_FAILURE);
    }

    // begin to read memory contents
    if (filename != NULL) {
        // open Mini-ELF file
        FILE *file = fopen(filename, "r");
        if (!file) {
            printf("Failed to read file\n");
            exit(EXIT_FAILURE);
        }

        // p1 read header
        elf_hdr_t hdr;
        if (!read_header(file, &hdr)) {
            printf("Failed to read file\n");
            exit(EXIT_FAILURE);
        }

        // p1 output
        if (print_header) {
            dump_header(hdr);
        }

        // p2 read each program header from the Mini-ELf file
        struct elf_phdr phdrs[hdr.e_num_phdr];
        uint32_t offset;
        int i;
        // loop through program headers
        for (i = 0, offset = hdr.e_phdr_start; i < hdr.e_num_phdr; i++, offset += PHDR_SIZE) {
            if (!read_phdr(file, offset, &phdrs[i])) {
                printf("Failed to read file\n");
                exit(EXIT_FAILURE);
            }
        }

        // p2 output print segments (no loading)
        if (print_segments) {
            dump_phdrs(hdr.e_num_phdr, phdrs);
        }

        // p2 read each segment of each program header from the Mini-ELF file
        byte_t* memory = (byte_t*)calloc(MEMSIZE, 1);
        for (int i = 0; i < hdr.e_num_phdr; i++) {
            if (!load_segment(file, memory, phdrs[i])) {
                printf("Failed to read file\n");
                exit(EXIT_FAILURE);
            }

            if (print_membrief) {
                dump_memory(memory, phdrs[i].p_vaddr, phdrs[i].p_vaddr + phdrs[i].p_filesz);
            }
        }

        if (print_memfull) {
            dump_memory(memory, 0, MEMSIZE);
        }

        // p3 executable output
        if (disas_code) {
            printf("Disassembly of executable contents:\n");
            for (int i = 0; i < hdr.e_num_phdr; i++) {  // loop through program headers (_start)
                disassemble_code(memory, &phdrs[i], &hdr);
            }
        }

        // p3 data output
        if (disas_data) {
            printf("Disassembly of data contents:\n");
            for (int i = 0; i < hdr.e_num_phdr; i++) {  // loop through program headers
                disassemble_rodata(memory, &phdrs[i]);
            }
        }

        // start of p4 output

        y86_t cpu;                          // main cpu struct
        memset(&cpu, 0x00, sizeof(cpu));    // clear register bits
        bool cnd = false;                   // condition signal

        y86_reg_t valA;                     // intermediate registers
        y86_reg_t valE;

        int count = 0;                      // execution count

        // initialize CPU
        cpu.stat = AOK;
        cpu.pc = hdr.e_entry;

        // normal CPU execution cycle
        if (exec_normal) {
            printf("Beginning execution at 0x%04x\n", hdr.e_entry);

            // loop while AOK status
            while (cpu.stat == AOK) {
                // fetch cycle
                y86_inst_t ins = fetch(&cpu, memory);

                // update decode to pc stages
                valE = decode_execute(&cpu, ins, &cnd, &valA);
                memory_wb_pc(&cpu, ins, memory, cnd, valA, valE);
                count++;    // update execution count
            }
            dump_cpu_state(cpu);    // print register values
            printf("Total execution count: %d\n", count);
        }

        // trace mode CPU execution cycle
        if (exec_trace) {
            printf("Beginning execution at 0x%04x\n", hdr.e_entry);

            // loop while AOK status
            while (cpu.stat == AOK) {
                // print normal CPU execution cycle
                dump_cpu_state(cpu);

                // fetch cycle
                y86_inst_t ins = fetch(&cpu, memory);

                // print individual execution
                printf("\nExecuting: ");
                disassemble(ins);
                printf("\n");

                // update decode to pc stages
                valE = decode_execute(&cpu, ins, &cnd, &valA);
                memory_wb_pc(&cpu, ins, memory, cnd, valA, valE);
                count++;    // update execution count
            }
            dump_cpu_state(cpu);    // prints last instruction
            printf("Total execution count: %d\n\n", count);
            dump_memory(memory, 0, MEMSIZE);
        }

        // take care of memory leaks
        fclose(file);
        free(memory);
    }

    return EXIT_SUCCESS;
}



