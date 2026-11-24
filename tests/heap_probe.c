#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile unsigned char *sink;

int main(void) {
  unsigned char *block = (unsigned char *)malloc(32);
  unsigned char stack_block[32];

  if (block == NULL) return 1;
  memset(block, 0x41, 48);
  sink = block;
  free(block);
  free(block);
  memset(stack_block, 0, sizeof(stack_block));
  free((void *)stack_block);
  printf("heap probe complete\n");
  return 0;
}
