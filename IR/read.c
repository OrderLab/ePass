#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <linux/bpf.h>
#include <stdint.h>
#include "read.h"

void print_item(FILE *fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
    int   i      = 0;
    char *sh_str = NULL;
    char *buff   = NULL;

    buff = malloc(sh_table[eh.e_shstrndx].sh_size);

    if (buff != NULL) {
        fseek(fd, sh_table[eh.e_shstrndx].sh_offset, SEEK_SET);
        fread(buff, 1, sh_table[eh.e_shstrndx].sh_size, fd);
    }
    sh_str = buff;

    for (i = 0; i < eh.e_shnum; i++) {
        if (!strcmp("xdp", (sh_str + sh_table[i].sh_name))) {
            printf("Found section\t\".text\"\n");
            printf("at offset\t0x%08x\n", (unsigned int)sh_table[i].sh_offset);
            printf("of size\t\t0x%08x\n", (unsigned int)sh_table[i].sh_size);
            break;
        }
    }

    if (i < eh.e_shnum) {
        uint64_t size     = sh_table[i].sh_size;
        uint32_t insn_cnt = size / 8;
        char    *mydata   = malloc(size);
        fseek(fd, sh_table[i].sh_offset, SEEK_SET);
        fread(mydata, 1, size, fd);
        struct bpf_insn *prog = (struct bpf_insn *)mydata;
        run(prog, size / sizeof(struct bpf_insn));
    }
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        return -1;
    }
    FILE       *fp           = NULL;  // Pointer used to access current file
    char       *program_name = NULL;
    Elf64_Shdr *sh_table     = NULL;  // Elf symbol table
    Elf64_Ehdr  elf_header;           // Elf header

    program_name = argv[1];
    fp           = fopen(program_name, "r");

    fseek(fp, 0, SEEK_SET);
    fread(&elf_header, 1, sizeof(Elf64_Ehdr), fp);
    sh_table = malloc(elf_header.e_shentsize * elf_header.e_shnum);

    fseek(fp, elf_header.e_shoff, SEEK_SET);
    fread(sh_table, 1, elf_header.e_shentsize * elf_header.e_shnum, fp);

    print_item(fp, elf_header, sh_table);

    return 0;
}
