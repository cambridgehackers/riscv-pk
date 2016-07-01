// See LICENSE for license details.

#include "file.h"
#include "pk.h"
#include "vm.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

file_t *file = 0;

ssize_t mem_pread(void *addr, void *buf, size_t n, off_t off)
{
  int nread = n;
  int chunksize = 1024;
  int chunk[1024];

  printk("mem_pread addr=%x n=%d off=%x buf=%x\n", addr, n, off, buf);
  memcpy(buf, ((char *)addr) + off, n);
  printk("mem_pread done\n");
  return nread;
}

void load_elf(void *elf_start, elf_info* info)
{
  void *kernel_elf_addr = elf_start;
  //file_t* file = 0;
  file = 0;
  printk("load_elf\n");
  printk("load_elf addr=%lx\n", kernel_elf_addr);

  Elf64_Ehdr eh64;
  printk("%s:%d %p\n", __FILE__, __LINE__, kernel_elf_addr);
  ssize_t ehdr_size = (kernel_elf_addr
		       ? mem_pread(kernel_elf_addr, &eh64, sizeof(eh64), 0)
		       : file_pread(file, &eh64, sizeof(eh64), 0));
  printk("ehdr_size=%d sizeof(eh64)=%d\n", ehdr_size, sizeof(eh64));
  printk("eh64.ident = %c %c %c\n", eh64.e_ident[1], eh64.e_ident[2], eh64.e_ident[3]);

  if (ehdr_size < (ssize_t)sizeof(eh64) ||
      !(eh64.e_ident[0] == '\177' && eh64.e_ident[1] == 'E' &&
        eh64.e_ident[2] == 'L'    && eh64.e_ident[3] == 'F'))
    goto fail;

  uintptr_t min_vaddr = -1, max_vaddr = 0;

  #define LOAD_ELF do { \
    eh = (typeof(eh))&eh64; \
    size_t phdr_size = eh->e_phnum*sizeof(*ph); \
    if (phdr_size > info->phdr_size) \
      goto fail; \
    ssize_t ret = (kernel_elf_addr \
		   ? mem_pread(kernel_elf_addr, (void*)info->phdr, phdr_size, eh->e_phoff) \
		   : file_pread(file, (void*)info->phdr, phdr_size, eh->e_phoff)); \
    if (ret < (ssize_t)phdr_size) \
      goto fail; \
    info->phnum = eh->e_phnum; \
    info->phent = sizeof(*ph); \
    ph = (typeof(ph))info->phdr; \
    info->is_supervisor = (eh->e_entry >> (8*sizeof(eh->e_entry)-1)) != 0; \
    if (info->is_supervisor) \
      info->first_free_paddr = ROUNDUP(info->first_free_paddr, SUPERPAGE_SIZE); \
    for (int i = 0; i < eh->e_phnum; i++) \
      if (ph[i].p_type == PT_LOAD && ph[i].p_memsz && ph[i].p_vaddr < min_vaddr) \
        min_vaddr = ph[i].p_vaddr; \
    if (info->is_supervisor) \
      min_vaddr = ROUNDDOWN(min_vaddr, SUPERPAGE_SIZE); \
    else \
      min_vaddr = ROUNDDOWN(min_vaddr, RISCV_PGSIZE); \
    uintptr_t bias = 0; \
    if (info->is_supervisor || eh->e_type == ET_DYN) \
      bias = info->first_free_paddr - min_vaddr; \
    info->entry = eh->e_entry; \
    if (!info->is_supervisor) { \
      info->entry += bias; \
      min_vaddr += bias; \
    } \
    info->bias = bias; \
    int flags = MAP_FIXED | MAP_PRIVATE; \
    if (info->is_supervisor) \
      flags |= MAP_POPULATE; \
    for (int i = eh->e_phnum - 1; i >= 0; i--) { \
      if(ph[i].p_type == PT_LOAD && ph[i].p_memsz) { \
        uintptr_t prepad = ph[i].p_vaddr % RISCV_PGSIZE; \
        uintptr_t vaddr = ph[i].p_vaddr + bias; \
        if (vaddr + ph[i].p_memsz > max_vaddr) \
          max_vaddr = vaddr + ph[i].p_memsz; \
        if (info->is_supervisor) { \
          if (!__valid_user_range(vaddr - prepad, vaddr + ph[i].p_memsz)) \
            goto fail; \
          ret = (kernel_elf_addr \
		 ? mem_pread(kernel_elf_addr, (void*)vaddr, ph[i].p_filesz, ph[i].p_offset) \
		 : file_pread(file, (void*)vaddr, ph[i].p_filesz, ph[i].p_offset)); \
          if (ret < (ssize_t)ph[i].p_filesz) \
            goto fail; \
          memset((void*)vaddr - prepad, 0, prepad); \
          memset((void*)vaddr + ph[i].p_filesz, 0, ph[i].p_memsz - ph[i].p_filesz); \
        } else { \
          int flags2 = flags | (prepad ? MAP_POPULATE : 0); \
          if (__do_mmap(vaddr - prepad, ph[i].p_filesz + prepad, -1, flags2, file, ph[i].p_offset - prepad) != vaddr - prepad) \
            goto fail; \
          memset((void*)vaddr - prepad, 0, prepad); \
          size_t mapped = ROUNDUP(ph[i].p_filesz + prepad, RISCV_PGSIZE) - prepad; \
          if (ph[i].p_memsz > mapped) \
            if (__do_mmap(vaddr + mapped, ph[i].p_memsz - mapped, -1, flags|MAP_ANONYMOUS, 0, 0) != vaddr + mapped) \
              goto fail; \
        } \
      } \
    } \
  } while(0)

  info->elf64 = IS_ELF64(eh64);
  if (info->elf64)
  {
    Elf64_Ehdr* eh;
    Elf64_Phdr* ph;
    LOAD_ELF;
  }
  else if (IS_ELF32(eh64))
  {
    Elf32_Ehdr* eh;
    Elf32_Phdr* ph;
    LOAD_ELF;
  }
  else
    goto fail;

  info->first_user_vaddr = min_vaddr;
  info->first_vaddr_after_user = ROUNDUP(max_vaddr - info->bias, RISCV_PGSIZE);
  info->brk_min = max_vaddr;

  printk("%s:%d\n", __FUNCTION__, __LINE__);
  //file_decref(file);
  return;

fail:
  printk("calling panic\n");
    panic("couldn't open ELF program: %lx!", elf_start);
}
