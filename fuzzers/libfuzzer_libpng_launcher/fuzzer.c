#include <malloc.h>
#include <stdio.h>
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  char *buffer = malloc(100);

  if (data[0] == 0x00) {
    printf("ZERO\n");
  }
  printf("buffer[0x100] = %d\n", buffer[0x100]);

  return 0;
}
