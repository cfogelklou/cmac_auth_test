
#include "bus_auth.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h> // for NULL

#define ASSERT(var)                        \
  do                                       \
  {                                        \
    if (!(var))                            \
    {                                      \
      AssertionFailed(__FILE__, __LINE__); \
    }                                      \
  } while (0)

#define ASSERT_WARN(var)                          \
  do                                              \
  {                                               \
    if (!(var))                                   \
    {                                             \
      AssertionWarningFailed(__FILE__, __LINE__); \
    }                                             \
  } while (0)

static void AssertionFailed(const char *const f, const int line)
{
  printf("BUS:Assertion Failed: %s(%d)\r\n", f, line);
  exit(-1);
}

static void AssertionWarningFailed(const char *const f, const int line)
{
  printf("BUS:Warning triggered at %s(%d)\r\n", f, line);
}

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

// ////////////////////////////////////////////////////////////////////////////
void *Malloc(const size_t sz)
{
  void *p = malloc(sz);
  ASSERT(p);
  return p;
}

// ////////////////////////////////////////////////////////////////////////////
void Free(void *pMem)
{
  ASSERT(pMem);
  free(pMem);
}

// ////////////////////////////////////////////////////////////////////////////
static uint8_t calcCs(const uint8_t *data, const size_t length)
{
  uint8_t cs = 0;
  for (size_t i = 0; i < length; i++)
  {
    cs ^= data[i];
  }
  return cs;
}

// ////////////////////////////////////////////////////////////////////////////
// Get the size of the whole packet, given the size of the "data" part
#define PACKET_SIZE(payloadSize) \
  sizeof(BusLineMessageHdr) + (payloadSize) + sizeof(BusLineMessageFtr)

// ////////////////////////////////////////////////////////////////////////////
static size_t getPacketSize(const BusLineMessage *const pM)
{
  return pM->hdr.length + sizeof(pM->hdr.addr) + sizeof(pM->hdr.length);
}

// ////////////////////////////////////////////////////////////////////////////
static const BusLineMessageFtr *getFtr(const BusLineMessage *const pM)
{
  const size_t len = getPacketSize(pM);
  const uint8_t *p0 = &pM->hdr.addr;
  const uint8_t *pFtr = &p0[len - 1];
  return (const BusLineMessageFtr *)pFtr;
}

// ////////////////////////////////////////////////////////////////////////////
// Use RAND() by default to generate challenge.
static void defaultrandombytesFn(void *p, uint8_t *pBuf, size_t bufLen)
{
  (void)p;
  for (size_t i = 0; i < bufLen; i++)
  {
    pBuf[i] = rand() & 0xff;
  }
}

// ////////////////////////////////////////////////////////////////////////////
int BusLineCheckCs(const BusLineMessage *const pM)
{
  const uint8_t cs0 = calcCs(&pM->hdr.addr, getPacketSize(pM) - 1);
  const BusLineMessageFtr *pFtr = getFtr(pM);
  return pFtr->cs - cs0;
}

// ////////////////////////////////////////////////////////////////////////////
uint8_t BusLineAddCs(BusLineMessage *const pM)
{
  const size_t pktSize = getPacketSize(pM);
  BusLineMessageFtr *pFtr = (BusLineMessageFtr *)getFtr(pM);
  pFtr->cs = calcCs(&pM->hdr.addr, pktSize - 1);
  return pFtr->cs;
}

// ////////////////////////////////////////////////////////////////////////////
BusLineMessage *BusLineAllocMessage(
    const uint8_t addr,
    const uint8_t func,
    const size_t payloadSize,
    void *pPayloadCanBeNull)
{
  const size_t sz = PACKET_SIZE(payloadSize);
  BusLineMessage *const pM = Malloc(sz);
  memset(pM, 0, sz);
  pM->hdr.addr = addr;
  pM->hdr.function = func;
  pM->hdr.length = 1 + (uint8_t)payloadSize + 1;
  if (payloadSize > 0)
  {
    if (pPayloadCanBeNull)
    {
      memcpy(pM->u.payload, pPayloadCanBeNull, payloadSize);
    }
    else
    {
      memset(pM->u.payload, 0, payloadSize);
    }
  }

  if (pPayloadCanBeNull || (0 == payloadSize))
  {
    BusLineAddCs(pM);
    ASSERT(0 == BusLineCheckCs(pM));
  }
  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
void BusLineFreeMessage(BusLineMessage *pM)
{
  Free(pM);
}

// ////////////////////////////////////////////////////////////////////////////
static void BusLineInitKey(
    BusLineAuthTxRx *pAuth,
    const uint8_t *const pKey)
{

  const mbedtls_cipher_info_t *const pCInfo =
      mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  ASSERT(NULL != pCInfo);
  mbedtls_cipher_init(&pAuth->cmac);

  int stat = mbedtls_cipher_setup(&pAuth->cmac, pCInfo);
  ASSERT(0 == stat);

  stat = mbedtls_cipher_cmac_starts(&pAuth->cmac, pKey, SK_BYTES * 8);
  ASSERT(0 == stat);

  // Finish and reset, so can be started again without referring to key.
  uint8_t tmp[16 + 1] = {0}; // plus one senty byte
  stat = mbedtls_cipher_cmac_finish(&pAuth->cmac, tmp);
  ASSERT(0 == stat);
  ASSERT(0 == tmp[16]);
  stat = mbedtls_cipher_cmac_reset(&pAuth->cmac);
  ASSERT(0 == stat);
}

// ////////////////////////////////////////////////////////////////////////////
void BusLineAuthDestruct(
    BusLineAuth *const pThis)
{
  mbedtls_cipher_free(&pThis->authRx.cmac);
  mbedtls_cipher_free(&pThis->authTx.cmac);
}

// ////////////////////////////////////////////////////////////////////////////
static void BusLineAuthPair(
    BusLineAuth *const pThis,
    bool isPakm,
    const BusLinePairing *const pPairing)
{
  const uint8_t *const pTxKey = (isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  BusLineInitKey(&pThis->authTx, pTxKey);

  const uint8_t *const pRxKey = (!isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  BusLineInitKey(&pThis->authRx, pRxKey);
}

// ////////////////////////////////////////////////////////////////////////////
void BusLineAuthInit(
    BusLineAuth *const pThis)
{
  uint8_t key[16];
  memset(pThis, 0, sizeof(BusLineAuth));

  // Randomize the keys.
  defaultrandombytesFn(NULL, key, SK_BYTES);
  BusLineInitKey(&pThis->authRx, key);
  defaultrandombytesFn(NULL, key, SK_BYTES);
  BusLineInitKey(&pThis->authTx, key);

  // Randomize the tx and rx nonces
  defaultrandombytesFn(NULL, pThis->authTx.nonce.entireNonce.byteArray, sizeof(pThis->authTx.nonce.entireNonce.byteArray));
  defaultrandombytesFn(NULL, pThis->authRx.nonce.entireNonce.byteArray, sizeof(pThis->authRx.nonce.entireNonce.byteArray));

  // Set rxcnt to 255, next message will fail.
  pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt = 255;
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the PAKM side
void BusLineAuthPairPAKM(
    BusLineAuth *const pThis,
    const BusLinePairing *pPairing)
{
  BusLineAuthPair(pThis, true, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the CEM side
void BusLineAuthPairCEM(
    BusLineAuth *const pThis,
    const BusLinePairing *pPairing)
{
  BusLineAuthPair(pThis, false, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
BusLineMessage *BusLineCreateChallenge(
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData,
    const size_t challengeLenBits)
{
  BusLineChallenge challenge = {{0}};

  ASSERT(0 == challengeLenBits % 8);
  const size_t challengeLen = (challengeLenBits >= 32) ? challengeLenBits / 8 : 120 / 8;
  const size_t cpyBytes = MIN(challengeLen, sizeof(challenge.challenge120));
  ASSERT(cpyBytes >= 4);

  RandombytesFnPtr rndFn = (randFn) ? randFn : defaultrandombytesFn;
  rndFn(randFnData, challenge.challenge120, cpyBytes);
  return BusLineAllocMessage(addr, func, cpyBytes, &challenge);
}

// ////////////////////////////////////////////////////////////////////////////
void BusLineReceiveAuthChallenge(
    BusLineAuth *const pThis,
    const BusLineChallenge *txChallenge,
    const BusLineChallenge *rxChallenge,
    const size_t challengeLenBits,
    // Set to non-null to allocate a response
    BusLineMessage **ppTxChallengeResponse

)
{
  ASSERT(0 == challengeLenBits % 8);
  const size_t challengeLen = (challengeLenBits >= 32) ? challengeLenBits / 8 : 120 / 8;
  const size_t cpyBytes = MIN(challengeLen, sizeof(txChallenge->challenge120));
  ASSERT(cpyBytes >= 4);

  // Zeroes at end of challenge if less than 120 bits are used.
  const size_t padBytes = sizeof(txChallenge->challenge120) - cpyBytes;

  if (txChallenge)
  {
    // Next sent message will use nonce of 0
    pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt = 1;
    memcpy(&pThis->authTx.nonce.txNoncePlusChallenge.challenge.challenge120[0], txChallenge, cpyBytes);
    memset(&pThis->authTx.nonce.txNoncePlusChallenge.challenge.challenge120[cpyBytes], 0, padBytes);
  }

  if (rxChallenge)
  {
    // Receiver believes its last received message is 0.
    pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt = 0;
    memcpy(&pThis->authRx.nonce.rxNoncePlusChallenge.challenge.challenge120[0], rxChallenge, cpyBytes);
    memset(&pThis->authRx.nonce.rxNoncePlusChallenge.challenge.challenge120[cpyBytes], 0, padBytes);
  }

  if (ppTxChallengeResponse)
  {
    *ppTxChallengeResponse = BusLineCreateAuthenticatedMessage(pThis, 0, 0, 0x80, NULL, 0);
  }
}

// ////////////////////////////////////////////////////////////////////////////
BusLineMessage *BusLineCreatePairing(
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData)
{
  RandombytesFnPtr rndFn = (randFn) ? randFn : defaultrandombytesFn;
  BusLinePairing pairing;
  rndFn(randFnData, pairing.cemToPak, sizeof(pairing.cemToPak));
  rndFn(randFnData, pairing.pakToCem, sizeof(pairing.pakToCem));
  return BusLineAllocMessage(addr, func, sizeof(pairing), &pairing);
}

// ////////////////////////////////////////////////////////////////////////////
static int cmacTag(
    BusLineAuthTxRx *const pAuth,
    const BusLineAuthMessage *const pMsg,
    uint8_t tag[SIGNATURE_BYTES])
{

  int stat = mbedtls_cipher_cmac_reset(&pAuth->cmac);
  ASSERT(0 == stat);

  // CMAC over NONCE
  stat = mbedtls_cipher_cmac_update(
      &pAuth->cmac,
      pAuth->nonce.entireNonce.byteArray,
      sizeof(pAuth->nonce.entireNonce.byteArray));
  ASSERT(0 == stat);

  // CMAC over sCMD and payload
  stat = mbedtls_cipher_cmac_update(
      &pAuth->cmac,
      pMsg->sdata.u.rawBytes,
      pMsg->hdr.sdata_len);
  ASSERT(0 == stat);

  // Calculate signature.
  uint8_t tagTmp[16 + 1] = {0}; // plus one sentry byte
  stat = mbedtls_cipher_cmac_finish(&pAuth->cmac, tagTmp);
  ASSERT(0 == stat);
  ASSERT(0 == tagTmp[sizeof(tagTmp) - 1]);

  // Use only 8 bytes of signature.
  memcpy(tag, tagTmp, SIGNATURE_BYTES);

  return stat;
}

#define AUTH_SCMD_KLINE_PAYLOAD_SZ(spayloadbytes) \
  (sizeof(BusLineAuthMessageHdr) + 1 + (spayloadbytes) + SIGNATURE_BYTES) // txcnt + sdata_len + scmd + spayload + tag

// ////////////////////////////////////////////////////////////////////////////
BusLineMessage *BusLineCreateAuthenticatedMessage(
    BusLineAuth *const pThis,
    const uint8_t addr,
    const uint8_t func,
    const uint8_t scmd,
    const void *sPayloadPtr,
    const size_t sb)
{
  const size_t sPayloadBytes = (sPayloadPtr) ? sb : 0;
  // Calculate the size of the data which will be signed.
  const size_t SDATA_LEN = 1 + sPayloadBytes; // scmd + sPayloadBytes;
  const size_t AUTH_SCMD_PAYLOAD_SZ = AUTH_SCMD_KLINE_PAYLOAD_SZ(sPayloadBytes);

  BusLineMessage *const pM = BusLineAllocMessage(addr, func, AUTH_SCMD_PAYLOAD_SZ, NULL);
  ASSERT(pM);

  // Set up headers and scmd
  pM->u.auth.hdr.txcnt = pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt;
  pM->u.auth.hdr.sdata_len = (uint8_t)SDATA_LEN;
  pM->u.auth.sdata.u.sdata.scmd = scmd;

  // Copy the signed payload
  if (sPayloadBytes > 0)
  {
    memcpy(pM->u.auth.sdata.u.sdata.spayload, sPayloadPtr, sPayloadBytes);
  }

  // Get pointer to ciphertext out and the signature out
  uint8_t *const tag = &pM->u.auth.sdata.u.sdata.spayload[sPayloadBytes];

  const int stat = cmacTag(&pThis->authTx, &pM->u.auth, tag);
  ASSERT(0 == stat);

  BusLineAddCs(pM);
  ASSERT(0 == BusLineCheckCs(pM));

  ++pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt;
  ASSERT(0 != pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt);

  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
bool BusLineAuthenticateMessage(
    BusLineAuth *const pThis,
    const BusLineMessage *const pMsgIn,
    const BusLineAuthMessage **ppSigned ///< outputs the signed part of the incoming data
)
{
  bool rval = false;
  ASSERT(pMsgIn);
  if (0 == BusLineCheckCs(pMsgIn))
  {

    // Check that received message is after last received message.
    const int messagesLost = pMsgIn->u.auth.hdr.txcnt - pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt - 1;
    if ((messagesLost >= 0) && (messagesLost <= MAX_MISSED_MESSAGES))
    {

      pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt = pMsgIn->u.auth.hdr.txcnt;

      const size_t sPayloadBytes = pMsgIn->u.auth.hdr.sdata_len - 1; // spayload

      const uint8_t *const tag = &pMsgIn->u.auth.sdata.u.sdata.spayload[sPayloadBytes];

      uint8_t tagTmp[SIGNATURE_BYTES] = {0};
      int stat = cmacTag(&pThis->authRx, &pMsgIn->u.auth, tagTmp);
      ASSERT(0 == stat);
      if (0 == stat)
      {
        stat = memcmp(tag, tagTmp, SIGNATURE_BYTES);
        ASSERT_WARN(0 == stat);
      }

      // Output variables
      if (0 == stat)
      {
        rval = true;
        if ((sPayloadBytes > 0) && (ppSigned))
        {
          *ppSigned = &pMsgIn->u.auth;
        }
      }
    }
  }

  return rval;
}

// ////////////////////////////////////////////////////////////////////////////
// Gets the current TXCNT (next message)
uint8_t BusLineAuthGetTxCnt(
    BusLineAuth *const pThis)
{
  return pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt;
}

// ////////////////////////////////////////////////////////////////////////////
// Gets the current RXCNT (last received message.)
uint8_t BusLineAuthGetRxCnt(
    BusLineAuth *const pThis)
{
  return pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt;
}

// ////////////////////////////////////////////////////////////////////////////
// Sets TX count, for test purposes.
void BusLineAuthSetTxCnt(
    BusLineAuth *const pThis,
    const uint8_t txcnt)
{
  pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt = txcnt;
}

// ////////////////////////////////////////////////////////////////////////////
void BusLineTestCmac(
    const uint8_t key[SK_BYTES],
    const uint8_t *buf,
    const size_t buflen,
    uint8_t signature[16])
{
  mbedtls_cipher_context_t cmac;
  const mbedtls_cipher_info_t *const pCInfo =
      mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  ASSERT(NULL != pCInfo);
  mbedtls_cipher_init(&cmac);

  int stat = mbedtls_cipher_setup(&cmac, pCInfo);
  ASSERT(0 == stat);

  stat = mbedtls_cipher_cmac_starts(&cmac, key, SK_BYTES * 8);
  ASSERT(0 == stat);

  if (buf)
  {
    // CMAC over NONCE
    stat = mbedtls_cipher_cmac_update(&cmac, buf, buflen);
    ASSERT(0 == stat);
  }

  // Finish and reset, so can be started again without referring to key.
  uint8_t tmp[16 + 1] = {0}; // plus one senty byte
  stat = mbedtls_cipher_cmac_finish(&cmac, tmp);
  ASSERT(0 == stat);
  ASSERT(0 == tmp[16]);

  memcpy(signature, tmp, 16);

  mbedtls_cipher_free(&cmac);
}

// /////////////////////////////////////////////////////////////////////////////
// Use Cifra for CMAC, mbedtls for AES.
// Note, this is how you can implement CMAC using your own AES ECB 128 implementation.
#include "mbedtls/aes.h"
#include "cifra/src/modes.h"

// Decrypt not used by CMAC, so place a dummy function here.
static void maes_decrypt(void *ctx, const uint8_t *in, uint8_t *out)
{
  // Should never get here.
  ASSERT(false);
};

// Encrypt is used by CMAC.
static void maes_encrypt(void *ctx, const uint8_t *in, uint8_t *out)
{
  mbedtls_aes_context *p = (mbedtls_aes_context *)ctx;
  mbedtls_aes_encrypt(p, in, out);
  return;
};

// /////////////////////////////////////////////////////////////////////////////
void BusLineTestCmacCifra(
    const uint8_t key[SK_BYTES],
    const uint8_t *buf,
    const size_t buflen,
    uint8_t signature[16])
{
  int stat = 0;
  mbedtls_aes_context enc;
  mbedtls_aes_init(&enc);
  mbedtls_aes_setkey_enc(&enc, key, SK_BYTES * 8);

  const cf_prp mbedtlsPrp = {
      16,           //size_t blocksz;
      maes_encrypt, //cf_prp_block encrypt;
      maes_decrypt  //cf_prp_block decrypt;
  };
  cf_cmac cmac = {
      &mbedtlsPrp, //const cf_prp *prp;
      &enc,        //void *prpctx;
      {0},
      {0}};

  cf_cmac_init(&cmac, &mbedtlsPrp, &enc);
  ASSERT(0 == stat);

  uint8_t tmp[16 + 1] = {0}; // plus one senty byte
  cf_cmac_sign(&cmac, buf, buflen, tmp);

  // Finish and reset, so can be started again without referring to key.
  ASSERT(0 == stat);
  ASSERT(0 == tmp[16]);

  memcpy(signature, tmp, 16);
  mbedtls_aes_free(&enc);
}
