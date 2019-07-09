#include "common.h"

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  if (errno != 0)
    return 1;

  return 0;
}
