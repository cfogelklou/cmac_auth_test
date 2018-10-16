#include <iostream>
#include <cstdlib>
#include <cassert>

#include "kline_auth.h"

using namespace std;

static void randombytes(void *p, uint8_t *pBuf, size_t bufLen) {
  (void)p;
  for (size_t i = 0; i < bufLen; i++) {
    pBuf[i] = rand() & 0xff;
  }
}


int main(char **c, int v) {

  const uint8_t *pSigned;
  size_t signedLen;
  const uint8_t *pPlainText;
  size_t plainTextLen;

  KLineMessage *pM;
  pM = KLineAllocMessage(0x12, 0x05, 0, nullptr);
  KLineFreeMessage(pM);

  KLineAuth pak;
  KLineAuth cem;  

  // CEM and PAK must pair with each other.
  pM = KLineCreatePairing(&cem, 0, 0, randombytes, NULL);
  KLineAuthPairCEM(&cem, &pM->u.pairing);
  KLineAuthPairPAKM(&pak, &pM->u.pairing);
  KLineFreeMessage(pM);

  // Generate a challenge, apply the CEM and PAK.
  pM = KLineCreateChallenge(&cem, 0, 0, randombytes, NULL);
  KLineAuthChallenge(&cem, &pM->u.challenge, &pM->u.challenge);
  KLineAuthChallenge(&pak, &pM->u.challenge, &pM->u.challenge);
  KLineFreeMessage(pM);

  // First test, signed message only.
  {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";
    //const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";

    pM = KLineAllocAuthenticatedMessage(
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

  // Second test, encrypted message only.
  {
    //const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";
    const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";

    pM = KLineAllocAuthenticatedMessage(
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

  // signed and encrypted messages... However, don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++) {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";
    const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";

    pM = KLineAllocAuthenticatedMessage(
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

  // Generate new challenge to reset txcnt to 1.
  pM = KLineCreateChallenge(&cem, 0, 0, randombytes, NULL);
  KLineAuthChallenge(&cem, &pM->u.challenge, &pM->u.challenge);
  KLineAuthChallenge(&pak, &pM->u.challenge, &pM->u.challenge);
  KLineFreeMessage(pM);

  // signed and encrypted messages... However, don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++) {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";
    const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";

    pM = KLineAllocAuthenticatedMessage(
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

  KLineAuthDestruct(&pak);
  KLineAuthDestruct(&cem);

  return 0;
}