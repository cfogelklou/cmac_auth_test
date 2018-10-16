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


  const uint8_t *pSigned;
  size_t signedLen;
  const uint8_t *pPlainText;
  size_t plainTextLen;
  {
    const char signedMsg[] = "signed";
    //const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      signedMsg, sizeof(signedMsg),
      NULL, 0);

    pPlainText = pSigned = NULL;
    plainTextLen = signedLen = 0;

    pM = KLineAllocDecryptMessage(
      &pak,
      pM,
      &pSigned, &signedLen, &pPlainText, &plainTextLen
      );

    assert(signedLen == sizeof(signedMsg));
    assert(0 == memcmp(pSigned, signedMsg, sizeof(signedMsg)));
    assert(plainTextLen == 0);
    assert(NULL == pPlainText);

    KLineFreeMessage(pM);
  }

#if 1
  {
    //const char signedMsg[] = "signed";
    const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      NULL, 0,
      encryptedMsg, sizeof(encryptedMsg));

    pPlainText = pSigned = NULL;
    plainTextLen = signedLen = 0;
    pM = KLineAllocDecryptMessage(
      &pak,
      pM,
      &pSigned, &signedLen, &pPlainText, &plainTextLen
    );

    assert(plainTextLen == sizeof(encryptedMsg));
    assert(0 == memcmp(pPlainText, encryptedMsg, sizeof(encryptedMsg)));
    assert(signedLen == 0);
    assert(NULL == pSigned);


    KLineFreeMessage(pM);
  }

  {
    const char signedMsg[] = "signed";
    const char encryptedMsg[] = "encrypted";

    pM = KLineAllocEncryptMessage(
      &cem, 0x12, 0x05,
      signedMsg, sizeof(signedMsg),
      encryptedMsg, sizeof(encryptedMsg));

    pPlainText = pSigned = NULL;
    plainTextLen = signedLen = 0;
    pM = KLineAllocDecryptMessage(
      &pak,
      pM,
      &pSigned, &signedLen, &pPlainText, &plainTextLen
    );

    assert(signedLen == sizeof(signedMsg));
    assert(0 == memcmp(pSigned, signedMsg, sizeof(signedMsg)));
    assert(plainTextLen == sizeof(encryptedMsg));
    assert(0 == memcmp(pPlainText, encryptedMsg, sizeof(encryptedMsg)));

    KLineFreeMessage(pM);
  }
#endif


  return 0;
}
