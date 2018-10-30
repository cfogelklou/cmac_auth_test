#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include "bus_auth.h"

using namespace std;

// ////////////////////////////////////////////////////////////////////////////
#define ASSERT(var) \
  do { \
    if (!(var)){AssertionFailed(__FILE__, __LINE__);} \
  } while(0) \

// ////////////////////////////////////////////////////////////////////////////
#define ASSERT_WARN(var) \
  do { \
    if (!(var)){AssertionWarningFailed(__FILE__, __LINE__);} \
  } while(0) \

// ////////////////////////////////////////////////////////////////////////////
static void AssertionFailed(const char * const f, const int line) {
  printf("Assertion Failed: %s(%d)\r\n", f, line);
  exit(-1);
}

// ////////////////////////////////////////////////////////////////////////////
static void AssertionWarningFailed(const char * const f, const int line) {
  printf("Warning triggered at %s(%d)\r\n", f, line);
}

// ////////////////////////////////////////////////////////////////////////////
// Replace with something cryptographically secure in a real implementation.
static void randombytes(void *p, uint8_t *pBuf, size_t bufLen) {
  (void)p;
  for (size_t i = 0; i < bufLen; i++) {
    pBuf[i] = rand() & 0xff;
  }
}

// ////////////////////////////////////////////////////////////////////////////
// Test case for first message from PAK to CEM after sleep.
static void wakeupTest() {
  const char signedMsg[] = "signed";
  KLineMessage *pTx;
  bool ok;
  KLineAuth pak;
  KLineAuth cem;

  KLineAuthInit(&pak);
  KLineAuthInit(&cem);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 != KLineAuthGetRxCnt(&cem));
  ASSERT_WARN(KLineAuthGetTxCnt(&pak) != KLineAuthGetRxCnt(&cem));

  // CEM and PAK must pair with each other.
  pTx = KLineCreatePairing(0, 0, randombytes, NULL);
  KLineAuthPairCEM(&cem, &pTx->u.pairing);
  KLineAuthPairPAKM(&pak, &pTx->u.pairing);
  KLineFreeMessage(pTx);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 != KLineAuthGetRxCnt(&cem));
  ASSERT_WARN(KLineAuthGetTxCnt(&pak) != KLineAuthGetRxCnt(&cem));

  // Allocate and send a message, which will FAIL as no challenge yet.
  pTx = KLineCreateAuthenticatedMessage( &pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = KLineAuthenticateMessage( &cem, pTx, NULL);
  KLineFreeMessage(pTx);
  ASSERT(false == ok);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = KLineCreateChallenge(0, 0, randombytes, NULL, 120);
  KLineReceiveAuthChallenge(&cem, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  
  // PAK will generate a challenge response
  {
    KLineMessage *pPakChallengeResponse = nullptr;

    // Receive challenge and generate response
    KLineReceiveAuthChallenge(&pak, &pTx->u.challenge, &pTx->u.challenge, 120, &pPakChallengeResponse);
    ASSERT(pPakChallengeResponse);

    // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 from the auth message)
    ASSERT_WARN(2 == KLineAuthGetTxCnt(&pak));
    ASSERT_WARN(0 == KLineAuthGetRxCnt(&cem));

    // Authenticate the challenge response
    ok = KLineAuthenticateMessage(&cem, pPakChallengeResponse, NULL);
    ASSERT(ok);

    // Free the response
    KLineFreeMessage(pPakChallengeResponse);
  }

  KLineFreeMessage(pTx);
  // Allocate and send a message, which will be OK as now there is a session
  pTx = KLineCreateAuthenticatedMessage(&pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = KLineAuthenticateMessage(&cem, pTx, NULL);
  ASSERT(ok);
  KLineFreeMessage(pTx);
  
}

// Test case for first message from PAK to CEM after sleep.
static void wakeupTest1() {
  const char signedMsg[] = "signed";
  KLineMessage *pTx;
  bool ok;
  KLineAuth pak;
  KLineAuth cem;

  KLineAuthInit(&pak);
  KLineAuthInit(&cem);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 != KLineAuthGetRxCnt(&cem));
  ASSERT_WARN(KLineAuthGetTxCnt(&pak) != KLineAuthGetRxCnt(&cem));

  // CEM and PAK must pair with each other.
  pTx = KLineCreatePairing(0, 0, randombytes, NULL);
  KLineAuthPairCEM(&cem, &pTx->u.pairing);
  KLineAuthPairPAKM(&pak, &pTx->u.pairing);
  KLineFreeMessage(pTx);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = KLineCreateChallenge(0, 0, randombytes, NULL, 120);
  KLineReceiveAuthChallenge(&cem, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  KLineReceiveAuthChallenge(&pak, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  KLineFreeMessage(pTx);

  // Set txcnt to 0 as this should cause first authentication to fail.
  KLineAuthSetTxCnt(&pak, 0);

  // Allocate and send a message, which will FAIL as txcnt is zero on the sent message.
  pTx = KLineCreateAuthenticatedMessage(&pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = KLineAuthenticateMessage(&cem, pTx, NULL);
  ASSERT(!ok);
  KLineFreeMessage(pTx);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = KLineCreateChallenge(0, 0, randombytes, NULL, 120);
  KLineReceiveAuthChallenge(&cem, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  KLineReceiveAuthChallenge(&pak, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  KLineFreeMessage(pTx);

  // RX Counter (last message received) set to 1, TXCNT set to 1
  ASSERT_WARN(1 == KLineAuthGetTxCnt(&pak));
  ASSERT_WARN(0 == KLineAuthGetRxCnt(&cem));

  // Allocate and send a message, which will be OK as now there is a session
  pTx = KLineCreateAuthenticatedMessage(&pak, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = KLineAuthenticateMessage(&cem, pTx, NULL);
  ASSERT(ok);
  KLineFreeMessage(pTx);

}

// ////////////////////////////////////////////////////////////////////////////
static void authTest0(const size_t challengeBits) {
  const KLineAuthMessage *pSigned;
  bool ok;
  KLineMessage *pM;
  pM = KLineAllocMessage(0x12, 0x05, 0, nullptr);
  KLineFreeMessage(pM);

  KLineAuth pak;
  KLineAuth cem;

  KLineAuthInit(&pak);
  KLineAuthInit(&cem);

  // CEM and PAK must pair with each other.
  pM = KLineCreatePairing(0, 0, randombytes, NULL);
  KLineAuthPairCEM(&cem, &pM->u.pairing);
  KLineAuthPairPAKM(&pak, &pM->u.pairing);
  KLineFreeMessage(pM);

  // Generate a challenge, apply the CEM and PAK.
  pM = KLineCreateChallenge(0, 0, randombytes, NULL, challengeBits);
  KLineReceiveAuthChallenge(&cem, &pM->u.challenge, &pM->u.challenge, challengeBits, nullptr);
  KLineReceiveAuthChallenge(&pak, &pM->u.challenge, &pM->u.challenge, challengeBits, nullptr);
  KLineFreeMessage(pM);

  // Don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++) {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";

    pM = KLineCreateAuthenticatedMessage(&cem, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));

    pSigned = NULL;
    ok = KLineAuthenticateMessage(&pak, pM, &pSigned);
    ASSERT(ok);

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload, signedMsg, sizeof(signedMsg)));

    KLineFreeMessage(pM);
  }

  // Generate new challenge to reset txcnt to 1.
  pM = KLineCreateChallenge(0, 0, randombytes, NULL, challengeBits);
  KLineReceiveAuthChallenge(&cem, &pM->u.challenge, &pM->u.challenge, challengeBits, nullptr);
  KLineReceiveAuthChallenge(&pak, &pM->u.challenge, &pM->u.challenge, challengeBits, nullptr);
  KLineFreeMessage(pM);

  // signed and encrypted messages... However, don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++) {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";

    pM = KLineCreateAuthenticatedMessage(
      &cem, 0x12, 0x05, 0x02,
      signedMsg, sizeof(signedMsg));

    pSigned = NULL;
    ok = KLineAuthenticateMessage( &pak,pM,&pSigned);
    ASSERT(ok);

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload, signedMsg, sizeof(signedMsg)));

    KLineFreeMessage(pM);
  }

  KLineAuthDestruct(&pak);
  KLineAuthDestruct(&cem);
}

// ////////////////////////////////////////////////////////////////////////////
int main(char **c, int v) {
  (void)c;
  (void)v;

  authTest0(120);
  wakeupTest();
  wakeupTest1();

  // Test with challenges of less than 120 bits (to save bandwidth)
  for (size_t challengeBits = 64; challengeBits < 120; challengeBits+=8) {
    authTest0(challengeBits);
  }

  return 0;
}
