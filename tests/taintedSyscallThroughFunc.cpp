#include "common.h"

void taintme(int fd) {
  close(fd);
}

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  taintme(fd);

  return 0;
}
