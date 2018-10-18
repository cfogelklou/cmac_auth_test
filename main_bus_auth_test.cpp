#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include "bus_auth.h"

using namespace std;

#define ASSERT(var) \
  do { \
    if (!(var)){AssertionFailed(__FILE__, __LINE__);} \
  } while(0) \

#define ASSERT_WARN(var) \
  do { \
    if (!(var)){AssertionWarningFailed(__FILE__, __LINE__);} \
  } while(0) \

static void AssertionFailed(const char * const f, const int line) {
  printf("Assertion Failed: %s(%d)\r\n", f, line);
  exit(-1);
}

static void AssertionWarningFailed(const char * const f, const int line) {
  printf("Warning triggered at %s(%d)\r\n", f, line);
}


static void randombytes(void *p, uint8_t *pBuf, size_t bufLen) {
  (void)p;
  for (size_t i = 0; i < bufLen; i++) {
    pBuf[i] = rand() & 0xff;
  }
}

// Test case for first message from PAK to CEM after sleep.
static void wakeupTest() {
  const char signedMsg[] = "signed";
  KLineMessage *pTx;
  KLineMessage *pRx;
  KLineAuth pak;
  KLineAuth cem;

  KLineAuthInit(&pak);
  KLineAuthInit(&cem);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 != KLineAuthGetRxCnt(&cem));
  ASSERT_WARN(KLineAuthGetTxCnt(&pak) != KLineAuthGetRxCnt(&cem));

  // CEM and PAK must pair with each other.
  pTx = KLineCreatePairing(&cem, 0, 0, randombytes, NULL);
  KLineAuthPairCEM(&cem, &pTx->u.pairing);
  KLineAuthPairPAKM(&pak, &pTx->u.pairing);
  KLineFreeMessage(pTx);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 != KLineAuthGetRxCnt(&cem));
  ASSERT_WARN(KLineAuthGetTxCnt(&pak) != KLineAuthGetRxCnt(&cem));

  // Allocate and send a message, which will FAIL as no challenge yet.
  pTx = KLineAllocAuthenticatedMessage( &pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg), NULL, 0);
  pRx = KLineAllocDecryptMessage( &cem, &pTx, NULL, NULL, NULL);
  ASSERT(NULL == pRx);
  if (pRx) { KLineFreeMessage(pRx); }

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = KLineCreateChallenge(&cem, 0, 0, randombytes, NULL);
  KLineAuthChallenge(&cem, &pTx->u.challenge, &pTx->u.challenge);
  KLineAuthChallenge(&pak, &pTx->u.challenge, &pTx->u.challenge);
  KLineFreeMessage(pTx);

  // RX Counter (last message received) set to 1, TXCNT set to 1
  ASSERT_WARN(1 == KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 == KLineAuthGetRxCnt(&cem));

  // Allocate and send a message, which will be OK as now there is a session
  pTx = KLineAllocAuthenticatedMessage(&pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg), NULL, 0);
  pRx = KLineAllocDecryptMessage(&cem, &pTx, NULL, NULL, NULL);
  ASSERT(NULL != pRx);
  if (pRx) { KLineFreeMessage(pRx); }
  
}

// Test case for first message from PAK to CEM after sleep.
static void wakeupTest1() {
  const char signedMsg[] = "signed";
  KLineMessage *pTx;
  KLineMessage *pRx;
  KLineAuth pak;
  KLineAuth cem;

  KLineAuthInit(&pak);
  KLineAuthInit(&cem);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 != KLineAuthGetRxCnt(&cem));
  ASSERT_WARN(KLineAuthGetTxCnt(&pak) != KLineAuthGetRxCnt(&cem));

  // CEM and PAK must pair with each other.
  pTx = KLineCreatePairing(&cem, 0, 0, randombytes, NULL);
  KLineAuthPairCEM(&cem, &pTx->u.pairing);
  KLineAuthPairPAKM(&pak, &pTx->u.pairing);
  KLineFreeMessage(pTx);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = KLineCreateChallenge(&cem, 0, 0, randombytes, NULL);
  KLineAuthChallenge(&cem, &pTx->u.challenge, &pTx->u.challenge);
  KLineAuthChallenge(&pak, &pTx->u.challenge, &pTx->u.challenge);
  KLineFreeMessage(pTx);

  KLineAuthSetTxCnt(&pak, 0);

  // Allocate and send a message, which will FAIL as no challenge yet.
  pTx = KLineAllocAuthenticatedMessage(&pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg), NULL, 0);
  pRx = KLineAllocDecryptMessage(&cem, &pTx, NULL, NULL, NULL);
  ASSERT(NULL == pRx);
  if (pRx) { KLineFreeMessage(pRx); }

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = KLineCreateChallenge(&cem, 0, 0, randombytes, NULL);
  KLineAuthChallenge(&cem, &pTx->u.challenge, &pTx->u.challenge);
  KLineAuthChallenge(&pak, &pTx->u.challenge, &pTx->u.challenge);
  KLineFreeMessage(pTx);

  // RX Counter (last message received) set to 1, TXCNT set to 1
  ASSERT_WARN(1 == KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 == KLineAuthGetRxCnt(&cem));

  // Allocate and send a message, which will be OK as now there is a session
  pTx = KLineAllocAuthenticatedMessage(&pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg), NULL, 0);
  pRx = KLineAllocDecryptMessage(&cem, &pTx, NULL, NULL, NULL);
  ASSERT(NULL != pRx);
  if (pRx) { KLineFreeMessage(pRx); }

}


static void authTest0() {
  const KLineAuthMessage *pSigned;
  const uint8_t *pPlainText;
  size_t plainTextLen;

  KLineMessage *pM;
  pM = KLineAllocMessage(0x12, 0x05, 0, nullptr);
  KLineFreeMessage(pM);

  KLineAuth pak;
  KLineAuth cem;

  KLineAuthInit(&pak);
  KLineAuthInit(&cem);

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
    const char signedMsg[] = "signed";
    //const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";
    
    pM = KLineAllocAuthenticatedMessage(
      &cem, 0x12, 0x05, 0x02,
      signedMsg, sizeof(signedMsg),
      NULL, 0);

    pPlainText = NULL;
    pSigned = NULL;
    plainTextLen = 0;

    pM = KLineAllocDecryptMessage(
      &pak,
      &pM,
      &pSigned, &pPlainText, &plainTextLen
    );

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload_and_edata, signedMsg, sizeof(signedMsg)));
    ASSERT(plainTextLen == 0);
    ASSERT(NULL == pPlainText);

    KLineFreeMessage(pM);
  }

  // Second test, encrypted message only.
  {
    //const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";
    const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";

    pM = KLineAllocAuthenticatedMessage(
      &cem, 0x12, 0x05, 0x02,
      NULL, 0,
      encryptedMsg, sizeof(encryptedMsg));

    pPlainText = NULL;
    pSigned = NULL;
    plainTextLen = 0;
    pM = KLineAllocDecryptMessage(
      &pak,
      &pM,
      &pSigned, &pPlainText, &plainTextLen
    );

    ASSERT(plainTextLen == sizeof(encryptedMsg));
    ASSERT(0 == memcmp(pPlainText, encryptedMsg, sizeof(encryptedMsg)));
    //ASSERT(signedLen == 0);
    ASSERT(NULL == pSigned);

    KLineFreeMessage(pM);
  }

  // signed and encrypted messages... However, don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++) {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";
    const char encryptedMsg[] = "encryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencryptedencrypted";

    pM = KLineAllocAuthenticatedMessage(
      &cem, 0x12, 0x05, 0x02,
      signedMsg, sizeof(signedMsg),
      encryptedMsg, sizeof(encryptedMsg));

    pPlainText = NULL;
    pSigned = NULL;
    plainTextLen = 0;
    pM = KLineAllocDecryptMessage(
      &pak,
      &pM,
      &pSigned, &pPlainText, &plainTextLen
    );

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload_and_edata, signedMsg, sizeof(signedMsg)));
    ASSERT(plainTextLen == sizeof(encryptedMsg));
    ASSERT(0 == memcmp(pPlainText, encryptedMsg, sizeof(encryptedMsg)));

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
      &cem, 0x12, 0x05, 0x02,
      signedMsg, sizeof(signedMsg),
      encryptedMsg, sizeof(encryptedMsg));

    pPlainText = NULL;
    pSigned = NULL;
    plainTextLen = 0;
    pM = KLineAllocDecryptMessage(
      &pak,
      &pM,
      &pSigned, &pPlainText, &plainTextLen
    );

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload_and_edata, signedMsg, sizeof(signedMsg)));
    ASSERT(plainTextLen == sizeof(encryptedMsg));
    ASSERT(0 == memcmp(pPlainText, encryptedMsg, sizeof(encryptedMsg)));

    KLineFreeMessage(pM);
  }

  KLineAuthDestruct(&pak);
  KLineAuthDestruct(&cem);
}


int main(char **c, int v) {

  authTest0();
  wakeupTest();
  wakeupTest1();

  return 0;
}
