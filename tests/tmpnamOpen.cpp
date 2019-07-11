#include "common.h"

int main() {
  if (open(tmpnam(NULL), O_RDONLY) < 0)
    return 1;

  return 0;
}
