#include "common.h"

int main() {
  if (!access("/dev/null", W_OK)) {
    if (open("/dev/null", O_RDONLY) < 0)
      return 1;
  }

  return 0;
}
