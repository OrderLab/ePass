#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <linux/bpf.h>
#include <cstdint>

void print_item(FILE *fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
    int   i;
    char *sh_str;
    char *buff;

    buff = malloc(sh_table[eh.e_shstrndx].sh_size);

    if (buff != NULL) {
        fseek(fd, sh_table[eh.e_shstrndx].sh_offset, SEEK_SET);
        fread(buff, 1, sh_table[eh.e_shstrndx].sh_size, fd);
    }
    sh_str = buff;

    for (i = 0; i < eh.e_shnum; i++) {
        // printf("Section %d: %s\n", i, (sh_str + sh_table[i].sh_name));
        if (!strcmp("xdp", (sh_str + sh_table[i].sh_name))) {
            printf("Found section\t\".text\"\n");
            printf("at offset\t0x%08x\n", (unsigned int)sh_table[i].sh_offset);
            printf("of size\t\t0x%08x\n", (unsigned int)sh_table[i].sh_size);
            break;
        }
    }

    /*Code to print or store string data*/
    if (i < eh.e_shnum) {
        uint64_t size     = sh_table[i].sh_size;
        uint32_t insn_cnt = size / 8;
        char    *mydata   = malloc(size);
        fseek(fd, sh_table[i].sh_offset, SEEK_SET);
        fread(mydata, 1, size, fd);
        for (int j = 0; j < size; j++) {
            printf("%d\n ", (uint8_t)mydata[j]);
        }
        // puts(mydata);
    }
}

int main() {
    FILE       *fp = NULL;  // Pointer used to access current file
    char       *program_name;
    Elf64_Ehdr  elf_header;  // Elf header
    Elf64_Shdr *sh_table;    // Elf symbol table

    program_name = "loop1.o";
    fp           = fopen(program_name, "r");

    fseek(fp, 0, SEEK_SET);
    fread(&elf_header, 1, sizeof(Elf64_Ehdr), fp);
    sh_table = malloc(elf_header.e_shentsize * elf_header.e_shnum);

    fseek(fp, elf_header.e_shoff, SEEK_SET);
    fread(sh_table, 1, elf_header.e_shentsize * elf_header.e_shnum, fp);

    print_item(fp, elf_header, sh_table);

    return 0;
}
