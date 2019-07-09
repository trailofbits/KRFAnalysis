#include "common.h"

int taintme(int fd) {
  return abs(fd);
}

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  taintme(fd);

  return 0;
}
