#include "common.h"

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  close(fd);

  return 0;
}
