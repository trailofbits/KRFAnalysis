#include "common.h"

void variadic(...) {
  return;
}

void taintme(int fd) {
  variadic(fd);
}

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  taintme(fd);

  return 0;
}
