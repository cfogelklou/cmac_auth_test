#include <iostream>
#include <cstdlib>
#include <cassert>

#include "kline_ccm.h"

using namespace std;



int main(char **c, int v) {

  KLineMessage *pM;
  pM = KLineAllocMessage(0x12, 0x05, 0, nullptr);
  KLineFreeMessage(pM);

  KLineCcm pak;
  KLineCcm cem;

  pM = KLineCreatePairing(&cem, 0, 0, NULL, NULL);
  KLineCcmInitCEM(&cem, &pM->u.pairing);
  KLineCcmInitPAKM(&pak, &pM->u.pairing);
  KLineFreeMessage(pM);

  pM = KLineCreateChallenge(&cem, 0, 0, NULL, NULL);
  KLineCcmChallenge(&cem, &pM->u.challenge, &pM->u.challenge);
  KLineCcmChallenge(&pak, &pM->u.challenge, &pM->u.challenge);
  KLineFreeMessage(pM);

  {
    const char signedMsg[] = "";
    //const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      signedMsg, 0,
      NULL, 0, &pak);

    pM = KLineAllocDecryptMessage(
      &pak,
      pM);

    KLineFreeMessage(pM);
  }


  {
    const char signedMsg[] = "signed";
    //const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      signedMsg, sizeof(signedMsg),
      NULL, 0, &pak);

    pM = KLineAllocDecryptMessage(
      &pak,
      pM);

    KLineFreeMessage(pM);
  }

#if 0
  {
    //const char signedMsg[] = "signed";
    const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      NULL, 0,
      encryptedMsg, sizeof(encryptedMsg));

    pM = KLineAllocDecryptMessage(
      &pak,
      pM);

    KLineFreeMessage(pM);
  }

  {
    const char signedMsg[] = "signed";
    const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      signedMsg, sizeof(signedMsg),
      encryptedMsg, sizeof(encryptedMsg));

    pM = KLineAllocDecryptMessage(
      &pak,
      pM);

    KLineFreeMessage(pM);
  }
#endif


  return 0;
}
