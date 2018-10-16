#include <iostream>
#include <cstdlib>
#include <cassert>

#include "kline_ccm.h"

using namespace std;



int main(char **c, int v) {  
  KLineMessage *pM = KLineAllocMessage(0x12, 0x05, 0, nullptr);

  KLineFreeMessage(pM);

  return 0;
}
