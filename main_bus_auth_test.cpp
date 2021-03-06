#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include "bus_auth.h"

using namespace std;

// ////////////////////////////////////////////////////////////////////////////
#define ASSERT(var)                        \
  do                                       \
  {                                        \
    if (!(var))                            \
    {                                      \
      AssertionFailed(__FILE__, __LINE__); \
    }                                      \
  } while (0)

// ////////////////////////////////////////////////////////////////////////////
#define ASSERT_WARN(var)                          \
  do                                              \
  {                                               \
    if (!(var))                                   \
    {                                             \
      AssertionWarningFailed(__FILE__, __LINE__); \
    }                                             \
  } while (0)

// ////////////////////////////////////////////////////////////////////////////
static void AssertionFailed(const char *const f, const int line)
{
  printf("Assertion Failed: %s(%d)\r\n", f, line);
  exit(-1);
}

// ////////////////////////////////////////////////////////////////////////////
static void AssertionWarningFailed(const char *const f, const int line)
{
  printf("Warning triggered at %s(%d)\r\n", f, line);
}

// ////////////////////////////////////////////////////////////////////////////
// Replace with something cryptographically secure in a real implementation.
static void randombytes(void *p, uint8_t *pBuf, size_t bufLen)
{
  (void)p;
  for (size_t i = 0; i < bufLen; i++)
  {
    pBuf[i] = rand() & 0xff;
  }
}

// ////////////////////////////////////////////////////////////////////////////
static void hexout(const char *name, const uint8_t buf[], const size_t len)
{
  cout << "const uint8_t " << name << "[] = {" << endl
       << "  ";
  for (size_t i = 0; i < len; i++)
  {
    cout << hex << "0x" << ((buf[i] & 0xf0) >> 4) << ((buf[i] & 0x0f) >> 0);
    if (i == (len - 1))
    {
      cout << endl
           << "};" << endl;
    }
    else
    {
      cout << ", ";
      if (0 == ((i + 1) % 8))
      {
        cout << endl
             << "  ";
      }
    }
  };
}

// ////////////////////////////////////////////////////////////////////////////
static std::string str2bin(const char *const buf, const size_t buflen)
{
  std::string bin;
  int byteIdx = 0;
  uint8_t byte = 0;
  for (size_t i = 0; i < buflen; i++)
  {
    uint8_t b = 0;
    const char c = tolower(buf[i]);
    bool valid = false;
    if ((c >= '0') && (c <= '9'))
    {
      b = (c - '0');
      valid = true;
    }
    else if ((c >= 'a') && (c <= 'f'))
    {
      b = (c - 'a' + 10);
      valid = true;
    }
    if (valid)
    {
      if (byteIdx == 1)
      {
        byte = ((byte << 4) | b);
        bin.push_back(byte);
      }
      else
      {
        byte = b;
      }
      byteIdx = (byteIdx + 1) % 2;
    }
  }
  return bin;
}

// ////////////////////////////////////////////////////////////////////////////
static void testVectorsCmac128Nist(const bool useCifra)
{
  auto cmac = (useCifra) ? BusLineTestCmacCifra : BusLineTestCmac;
  cout << "Running testVectorsCmac128Nist()...";
  if (useCifra)
  {
    cout << "cifra cmac + mbedtls aes...";
  }
  else
  {
    cout << "pure mbedtls...";
  }
  uint8_t signature[16];
  // Test vectors are from
  // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
  const char skstr[] = "2b7e1516 28aed2a6 abf71588 09cf4f3c";
  std::string keybin = str2bin(skstr, sizeof(skstr));
  ASSERT_WARN(keybin.length() == 16);
  {
    // Example 1: Mlen 0
    const uint8_t m[] = {0};
    const size_t mlen = 0;
    const char tagstr[] = "bb1d6929 e9593728 7fa37d12 9b756746";
    std::string tagbin = str2bin(tagstr, sizeof(tagstr));
    cmac((uint8_t *)keybin.data(), m, mlen, signature);

    ASSERT(0 == memcmp(signature, tagbin.data(), sizeof(signature)));
  }

  {
    // Example 1: Mlen 128
    const char mstr[] = "6bc1bee2 2e409f96 e93d7e11 7393172a";
    std::string mbin = str2bin(mstr, sizeof(mstr));
    const uint8_t *m = (const uint8_t *)mbin.data();
    const size_t mlen = mbin.length();
    const char tagstr[] = "070a16b4 6b4d4144 f79bdd9d d04a287c";
    std::string tagbin = str2bin(tagstr, sizeof(tagstr));
    cmac((uint8_t *)keybin.data(), m, mlen, signature);

    ASSERT(0 == memcmp(signature, tagbin.data(), sizeof(signature)));
  }

  {
    // Example 1: Mlen 320
    const char mstr[] =
        "6bc1bee2 2e409f96 e93d7e11 7393172a"
        "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
        "30c81c46 a35ce411";
    std::string mbin = str2bin(mstr, sizeof(mstr));
    const uint8_t *m = (const uint8_t *)mbin.data();
    const size_t mlen = mbin.length();
    const char tagstr[] = "dfa66747 de9ae630 30ca3261 1497c827";
    std::string tagbin = str2bin(tagstr, sizeof(tagstr));
    cmac((uint8_t *)keybin.data(), m, mlen, signature);

    ASSERT(0 == memcmp(signature, tagbin.data(), sizeof(signature)));
  }

  {
    // Example 1: Mlen 512
    const char mstr[] =
        "6bc1bee2 2e409f96 e93d7e11 7393172a"
        "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
        "30c81c46 a35ce411 e5fbc119 1a0a52ef"
        "f69f2445 df4f9b17 ad2b417b e66c3710";
    std::string mbin = str2bin(mstr, sizeof(mstr));
    const uint8_t *m = (const uint8_t *)mbin.data();
    const size_t mlen = mbin.length();
    const char tagstr[] = "51f0bebf 7e3b9d92 fc497417 79363cfe";
    std::string tagbin = str2bin(tagstr, sizeof(tagstr));
    cmac((uint8_t *)keybin.data(), m, mlen, signature);

    ASSERT(0 == memcmp(signature, tagbin.data(), sizeof(signature)));
  }
  cout << "ok." << endl;
}

// ////////////////////////////////////////////////////////////////////////////
static void testVectors()
{
  cout << "Running testVectors()...";
  bool ok;
  BusLineAuth bus_slave;
  BusLineAuth bus_master;

  const BusLinePairing pairing = {
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

  const BusLineChallenge challenge = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}};

  BusLineAuthInit(&bus_slave);
  BusLineAuthInit(&bus_master);

  // CEM and PAK must pair with each other.
  BusLineMessage *pM = BusLineCreatePairing(0, 0, randombytes, NULL);
  memcpy(&pM->u.pairing, &pairing, sizeof(pairing));
  BusLineAuthPairCEM(&bus_master, &pM->u.pairing);
  BusLineAuthPairPAKM(&bus_slave, &pM->u.pairing);
  BusLineFreeMessage(pM);

  // Generate a challenge, apply the CEM and PAK.
  pM = BusLineCreateChallenge(0, 0, randombytes, NULL, 120);
  memcpy(&pM->u.challenge, &challenge, sizeof(challenge));
  BusLineReceiveAuthChallenge(&bus_master, &pM->u.challenge, &pM->u.challenge, 120, nullptr);
  // PAK will generate a challenge response
  {
    BusLineMessage *pPakChallengeResponse = nullptr;

    // Receive challenge and generate response
    BusLineReceiveAuthChallenge(&bus_slave, &pM->u.challenge, &pM->u.challenge, 120, &pPakChallengeResponse);
    ASSERT(pPakChallengeResponse);

    //hexout("pPakChallengeResponse", (uint8_t *)pPakChallengeResponse, pPakChallengeResponse->hdr.length + 2);

    const uint8_t expectedResponse[] = {
        0x00, 0x0d, 0x00, 0x01, 0x01, 0x80, 0xf0, 0x5d,
        0xf7, 0x4a, 0x80, 0xfd, 0x01, 0x77, 0x96};

    // Check that the signature matches the expected signature
    ASSERT(0 == memcmp(expectedResponse, pPakChallengeResponse, sizeof(expectedResponse)));

    // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 from the auth message)
    ASSERT_WARN(2 == BusLineAuthGetTxCnt(&bus_slave));
    ASSERT_WARN(0 == BusLineAuthGetRxCnt(&bus_master));

    // Authenticate the challenge response
    ok = BusLineAuthenticateMessage(&bus_master, pPakChallengeResponse, NULL);
    ASSERT(ok);

    // Check that rxcount for CEM is now 1 after the challenge.
    ASSERT_WARN(1 == BusLineAuthGetRxCnt(&bus_master));

    // Free the response
    BusLineFreeMessage(pPakChallengeResponse);
  }

  BusLineFreeMessage(pM);
  {
    const char hello[] = "hello";
    BusLineMessage *pTx = BusLineCreateAuthenticatedMessage(&bus_master, 0x11, 0x22, 0x33, hello, sizeof(hello));
    //hexout("expectedTx", (uint8_t *)pTx, pTx->hdr.length + 2);

    const uint8_t expectedTx[] = {
        0x11, 0x13, 0x22, 0x01, 0x07, 0x33, 0x68, 0x65,
        0x6c, 0x6c, 0x6f, 0x00, 0x5f, 0xc5, 0xe6, 0x9f,
        0x27, 0x25, 0x17, 0xc5, 0x44};

    // Check that the signature matches the expected signature
    ASSERT(0 == memcmp(expectedTx, pTx, sizeof(expectedTx)));

    BusLineFreeMessage(pTx);
  }

  BusLineAuthDestruct(&bus_slave);
  BusLineAuthDestruct(&bus_master);
  cout << "ok." << endl;
}

// ////////////////////////////////////////////////////////////////////////////
// Test case for first message from PAK to CEM after sleep.
static void wakeupTest()
{
  cout << "Running wakeupTest()...";
  const char signedMsg[] = "signed";
  BusLineMessage *pTx;
  bool ok;
  BusLineAuth bus_slave;
  BusLineAuth bus_master;

  BusLineAuthInit(&bus_slave);
  BusLineAuthInit(&bus_master);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != BusLineAuthGetTxCnt(&bus_slave));
  ASSERT_WARN(0 != BusLineAuthGetRxCnt(&bus_master));
  ASSERT_WARN(BusLineAuthGetTxCnt(&bus_slave) != BusLineAuthGetRxCnt(&bus_master));

  // CEM and PAK must pair with each other.
  pTx = BusLineCreatePairing(0, 0, randombytes, NULL);
  BusLineAuthPairCEM(&bus_master, &pTx->u.pairing);
  BusLineAuthPairPAKM(&bus_slave, &pTx->u.pairing);
  BusLineFreeMessage(pTx);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != BusLineAuthGetTxCnt(&bus_slave));
  ASSERT_WARN(0 != BusLineAuthGetRxCnt(&bus_master));
  ASSERT_WARN(BusLineAuthGetTxCnt(&bus_slave) != BusLineAuthGetRxCnt(&bus_master));

  // Allocate and send a message, which will FAIL as no challenge yet.
  pTx = BusLineCreateAuthenticatedMessage(&bus_slave, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = BusLineAuthenticateMessage(&bus_master, pTx, NULL);
  BusLineFreeMessage(pTx);
  ASSERT(false == ok);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = BusLineCreateChallenge(0, 0, randombytes, NULL, 120);
  BusLineReceiveAuthChallenge(&bus_master, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);

  // PAK will generate a challenge response
  {
    BusLineMessage *pPakChallengeResponse = nullptr;

    // Receive challenge and generate response
    BusLineReceiveAuthChallenge(&bus_slave, &pTx->u.challenge, &pTx->u.challenge, 120, &pPakChallengeResponse);
    ASSERT(pPakChallengeResponse);

    // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 from the auth message)
    ASSERT_WARN(2 == BusLineAuthGetTxCnt(&bus_slave));
    ASSERT_WARN(0 == BusLineAuthGetRxCnt(&bus_master));

    // Authenticate the challenge response
    ok = BusLineAuthenticateMessage(&bus_master, pPakChallengeResponse, NULL);
    ASSERT(ok);

    // Check that rxcount for CEM is now 1 after the challenge.
    ASSERT_WARN(1 == BusLineAuthGetRxCnt(&bus_master));

    // Free the response
    BusLineFreeMessage(pPakChallengeResponse);
  }

  BusLineFreeMessage(pTx);
  // Allocate and send a message, which will be OK as now there is a session
  pTx = BusLineCreateAuthenticatedMessage(&bus_slave, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = BusLineAuthenticateMessage(&bus_master, pTx, NULL);
  ASSERT(ok);
  BusLineFreeMessage(pTx);

  cout << "ok." << endl;
}

// Test case for first message from PAK to CEM after sleep.
static void wakeupTest1()
{
  cout << "Running wakeupTest1()...";
  const char signedMsg[] = "signed";
  BusLineMessage *pTx;
  bool ok;
  BusLineAuth bus_slave;
  BusLineAuth bus_master;

  BusLineAuthInit(&bus_slave);
  BusLineAuthInit(&bus_master);

  // Counters should not match and should not be zero as no challenge yet.
  ASSERT_WARN(0 != BusLineAuthGetTxCnt(&bus_slave));
  ASSERT_WARN(0 != BusLineAuthGetRxCnt(&bus_master));
  ASSERT_WARN(BusLineAuthGetTxCnt(&bus_slave) != BusLineAuthGetRxCnt(&bus_master));

  // CEM and PAK must pair with each other.
  pTx = BusLineCreatePairing(0, 0, randombytes, NULL);
  BusLineAuthPairCEM(&bus_master, &pTx->u.pairing);
  BusLineAuthPairPAKM(&bus_slave, &pTx->u.pairing);
  BusLineFreeMessage(pTx);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = BusLineCreateChallenge(0, 0, randombytes, NULL, 120);
  BusLineReceiveAuthChallenge(&bus_master, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  BusLineReceiveAuthChallenge(&bus_slave, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  BusLineFreeMessage(pTx);

  // Set txcnt to 0 as this should cause first authentication to fail.
  BusLineAuthSetTxCnt(&bus_slave, 0);

  // Allocate and send a message, which will FAIL as txcnt is zero on the sent message.
  pTx = BusLineCreateAuthenticatedMessage(&bus_slave, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = BusLineAuthenticateMessage(&bus_master, pTx, NULL);
  ASSERT(!ok);
  BusLineFreeMessage(pTx);

  // CEM detects failure, and generates a challenge, then broadcasts it to PAK.
  // Currently only CEM generates the challenge.
  pTx = BusLineCreateChallenge(0, 0, randombytes, NULL, 120);
  BusLineReceiveAuthChallenge(&bus_master, &pTx->u.challenge, &pTx->u.challenge, 120, nullptr);
  // PAK will generate a challenge response
  {
    BusLineMessage *pPakChallengeResponse = nullptr;

    // Receive challenge and generate response
    BusLineReceiveAuthChallenge(&bus_slave, &pTx->u.challenge, &pTx->u.challenge, 120, &pPakChallengeResponse);
    ASSERT(pPakChallengeResponse);

    // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 from the auth message)
    ASSERT_WARN(2 == BusLineAuthGetTxCnt(&bus_slave));
    ASSERT_WARN(0 == BusLineAuthGetRxCnt(&bus_master));

    // Authenticate the challenge response
    ok = BusLineAuthenticateMessage(&bus_master, pPakChallengeResponse, NULL);
    ASSERT(ok);

    // Free the response
    BusLineFreeMessage(pPakChallengeResponse);
  }

  BusLineFreeMessage(pTx);

  // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 for challenge response)
  ASSERT_WARN(2 == BusLineAuthGetTxCnt(&bus_slave));

  // bus_master has received one authentication message, so
  // it should have rxcount of 1.
  ASSERT_WARN(1 == BusLineAuthGetRxCnt(&bus_master));

  // Allocate and send a message, which will be OK as now there is a session
  pTx = BusLineCreateAuthenticatedMessage(&bus_slave, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));
  ok = BusLineAuthenticateMessage(&bus_master, pTx, NULL);
  ASSERT(ok);
  BusLineFreeMessage(pTx);

  cout << "ok." << endl;
}

// ////////////////////////////////////////////////////////////////////////////
static void authTestWithVariableChallengeBits(const size_t challengeBits)
{
  cout << "Running authTestWithVariableChallengeBits( " << dec << challengeBits << " )...";
  const BusLineAuthMessage *pSigned;
  bool ok;
  BusLineMessage *pM;

  BusLineAuth bus_slave;
  BusLineAuth bus_master;

  BusLineAuthInit(&bus_slave);
  BusLineAuthInit(&bus_master);

  // CEM and PAK must pair with each other.
  pM = BusLineCreatePairing(0, 0, randombytes, NULL);
  BusLineAuthPairCEM(&bus_master, &pM->u.pairing);
  BusLineAuthPairPAKM(&bus_slave, &pM->u.pairing);
  BusLineFreeMessage(pM);

  // Generate a challenge, apply the CEM and PAK.
  pM = BusLineCreateChallenge(0, 0, randombytes, NULL, challengeBits);
  BusLineReceiveAuthChallenge(&bus_master, &pM->u.challenge, &pM->u.challenge, challengeBits, nullptr);
  // PAK will generate a challenge response
  {
    BusLineMessage *pPakChallengeResponse = nullptr;

    // Receive challenge and generate response
    BusLineReceiveAuthChallenge(&bus_slave, &pM->u.challenge, &pM->u.challenge, challengeBits, &pPakChallengeResponse);
    ASSERT(pPakChallengeResponse);

    // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 from the auth message)
    ASSERT_WARN(2 == BusLineAuthGetTxCnt(&bus_slave));
    ASSERT_WARN(0 == BusLineAuthGetRxCnt(&bus_master));

    // Authenticate the challenge response
    ok = BusLineAuthenticateMessage(&bus_master, pPakChallengeResponse, NULL);
    ASSERT(ok);
    ASSERT_WARN(1 == BusLineAuthGetRxCnt(&bus_master));

    // Free the response
    BusLineFreeMessage(pPakChallengeResponse);
  }

  BusLineFreeMessage(pM);
  // Don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++)
  {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";

    pM = BusLineCreateAuthenticatedMessage(&bus_master, 0x12, 0x05, 0x02, signedMsg, sizeof(signedMsg));

    pSigned = NULL;
    ok = BusLineAuthenticateMessage(&bus_slave, pM, &pSigned);
    ASSERT(ok);

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload, signedMsg, sizeof(signedMsg)));

    BusLineFreeMessage(pM);
  }

  // Generate new challenge to reset txcnt to 1.
  pM = BusLineCreateChallenge(0, 0, randombytes, NULL, challengeBits);
  BusLineReceiveAuthChallenge(&bus_master, &pM->u.challenge, &pM->u.challenge, challengeBits, nullptr);
  // PAK will generate a challenge response
  {
    BusLineMessage *pPakChallengeResponse = nullptr;

    // Receive challenge and generate response
    BusLineReceiveAuthChallenge(&bus_slave, &pM->u.challenge, &pM->u.challenge, challengeBits, &pPakChallengeResponse);
    ASSERT(pPakChallengeResponse);

    // RX Counter (last message received) set to 1, TXCNT set to 1 (+1 from the auth message)
    ASSERT_WARN(2 == BusLineAuthGetTxCnt(&bus_slave));
    ASSERT_WARN(0 == BusLineAuthGetRxCnt(&bus_master));

    // Authenticate the challenge response
    ok = BusLineAuthenticateMessage(&bus_master, pPakChallengeResponse, NULL);
    ASSERT(ok);

    ASSERT_WARN(1 == BusLineAuthGetRxCnt(&bus_master));

    // Free the response
    BusLineFreeMessage(pPakChallengeResponse);
  }

  BusLineFreeMessage(pM);

  // signed and encrypted messages... However, don't let txcnt roll over (which it will if i >= 255)
  for (int i = 0; i < 200; i++)
  {
    const char signedMsg[] = "signedsignedsignedsignedsignedsignedsignedsignedsigned";

    pM = BusLineCreateAuthenticatedMessage(
        &bus_master, 0x12, 0x05, 0x02,
        signedMsg, sizeof(signedMsg));

    pSigned = NULL;
    ok = BusLineAuthenticateMessage(&bus_slave, pM, &pSigned);
    ASSERT(ok);

    ASSERT(pSigned->hdr.sdata_len == 1 + sizeof(signedMsg));
    ASSERT(0 == memcmp(pSigned->sdata.u.sdata.spayload, signedMsg, sizeof(signedMsg)));

    BusLineFreeMessage(pM);
  }

  BusLineAuthDestruct(&bus_slave);
  BusLineAuthDestruct(&bus_master);

  cout << "ok." << endl;
}

// ////////////////////////////////////////////////////////////////////////////
int main(int v, char **c)
{
  (void)c;
  (void)v;

  testVectorsCmac128Nist(false);
  testVectorsCmac128Nist(true);
  testVectors();

  wakeupTest();
  wakeupTest1();

  // Test with challenges of less than 120 bits (to save bandwidth)
  for (size_t challengeBits = 64; challengeBits <= 120; challengeBits += 8)
  {
    authTestWithVariableChallengeBits(challengeBits);
  }

  return 0;
}
