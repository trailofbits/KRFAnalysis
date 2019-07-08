#include "common.h"

int main() {
  int fd;
  fd = open("/dev/null", O_RDONLY);

  if ((fd < 0) || (errno != 0))
    return 1;

  return 0;
}
