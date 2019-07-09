#include "common.h"

void variadic(...) {
  return;
}

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  variadic(fd);

  return 0;
}
