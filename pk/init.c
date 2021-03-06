// See LICENSE for license details.

#include "pk.h"
#include "file.h"
#include "vm.h"
#include "frontend.h"
#include "elf.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

elf_info current;
int have_vm = 1; // unless -p flag is given

int uarch_counters_enabled;
long uarch_counters[NUM_COUNTERS];
char* uarch_counter_names[NUM_COUNTERS];

void init_tf(trapframe_t* tf, long pc, long sp, int user64)
{
  memset(tf, 0, sizeof(*tf));
#ifdef __riscv64
  if (!user64)
    panic("can't run 32-bit ELF on 64-bit pk");
#else
  if (user64)
    panic("can't run 64-bit ELF on 32-bit pk");
#endif
  tf->status = read_csr(sstatus);
  tf->gpr[2] = sp;
  tf->epc = pc;
}

static void handle_option(const char* s)
{
  switch (s[1])
  {
    case 's': // print cycle count upon termination
      current.t0 = 1;
      break;

    case 'c': // print uarch counters upon termination
              // If your HW doesn't support uarch counters, then don't use this flag!
      uarch_counters_enabled = 1;
      break;

  case 'p':
  case 'm':
      // skip legacy option
      break;
    default:
      panic("unrecognized option: `%c'", s[1]);
      break;
  }
}

struct mainvars* parse_args(struct mainvars* args)
{
  long r = frontend_syscall(SYS_getmainvars, (uintptr_t)args, sizeof(*args), 0, 0, 0, 0, 0);
  kassert(r == 0);

  // argv[0] is the proxy kernel itself.  skip it and any flags.
  {
    unsigned a0;
    for (a0 = 1; a0 < args->argc; a0++)
      printk("  argv[%d] = %s\n", a0, args->argv[a0]);
  }
  unsigned a0 = 1;
  for ( ; a0 < args->argc && *(char*)(uintptr_t)args->argv[a0] == '-'; a0++)
    handle_option((const char*)(uintptr_t)args->argv[a0]);
  args->argv[a0-1] = args->argc - a0;
  return (struct mainvars*)&args->argv[a0-1];
}

void boot_loader(void *elf_start)
{
  // load program named by argv[0]
  long phdrs[128];
  current.phdr = (uintptr_t)phdrs;
  current.phdr_size = sizeof(phdrs);
  load_elf(elf_start, &current);

  run_loaded_program(elf_start);
}
