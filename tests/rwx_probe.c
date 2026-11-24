#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
  size_t page = 4096u;
  unsigned char *memory = mmap(NULL, page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  long result;
  int saved;

  if (memory == MAP_FAILED) {
    printf("mmap=failed errno=%d\n", errno);
    return 1;
  }
  printf("before_mprotect\n");
  fflush(stdout);
  result = mprotect(memory, page, PROT_READ | PROT_WRITE | PROT_EXEC);
  saved = errno;
  printf("mprotect=%ld errno=%d\n", result, result == 0 ? 0 : saved);
  return 0;
}
