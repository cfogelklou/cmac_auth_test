
#include "bus_auth.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h> // for NULL

#define ASSERT(var) \
  do { \
    if (!(var)){AssertionFailed(__FILE__, __LINE__);} \
  } while(0) \

#define ASSERT_WARN(var) \
  do { \
    if (!(var)){AssertionWarningFailed(__FILE__, __LINE__);} \
  } while(0) \

static void AssertionFailed(const char * const f, const int line) {
  printf("BUS:Assertion Failed: %s(%d)\r\n", f, line);
  exit(-1);
}

static void AssertionWarningFailed(const char * const f, const int line) {
  printf("BUS:Warning triggered at %s(%d)\r\n", f, line);
}

#ifndef MIN
#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x,y) (((x) > (y)) ? (x) : (y))
#endif

// ////////////////////////////////////////////////////////////////////////////
void *Malloc(const size_t sz) {
  void *p = malloc(sz);
  ASSERT(p);
  return p;
}

// ////////////////////////////////////////////////////////////////////////////
void Free(void *pMem) {
  ASSERT(pMem);
  free(pMem);
}

// ////////////////////////////////////////////////////////////////////////////
static uint8_t calcCs(const uint8_t *data, const size_t length) {
  uint8_t cs = 0;
  for (size_t i = 0; i < length; i++) {
    cs ^= data[i];
  }
  return cs;
}

// ////////////////////////////////////////////////////////////////////////////
// Get the size of the whole packet, given the size of the "data" part
#define PACKET_SIZE(payloadSize) \
  sizeof(KLineMessageHdr) + (payloadSize) + sizeof(KLineMessageFtr)

// ////////////////////////////////////////////////////////////////////////////
static size_t getPacketSize(const KLineMessage * const pM) {
  return pM->hdr.length + sizeof(pM->hdr.addr) + sizeof(pM->hdr.length);
}

// ////////////////////////////////////////////////////////////////////////////
static const KLineMessageFtr *getFtr(const KLineMessage * const pM) {
  const size_t len = getPacketSize(pM);
  const uint8_t *p0 = &pM->hdr.addr;
  const uint8_t *pFtr = &p0[len - 1];
  return (const KLineMessageFtr *)pFtr;
}

// ////////////////////////////////////////////////////////////////////////////
// Use RAND() by default to generate challenge.
static void defaultrandombytesFn(void *p, uint8_t *pBuf, size_t bufLen) {
  (void)p;
  for (size_t i = 0; i < bufLen; i++) {
    pBuf[i] = rand() & 0xff;
  }
}

// ////////////////////////////////////////////////////////////////////////////
int KLineCheckCs(const KLineMessage * const pM) {
  const uint8_t cs0 = calcCs(&pM->hdr.addr, getPacketSize(pM) - 1);
  const KLineMessageFtr * pFtr = getFtr(pM);
  return pFtr->cs - cs0;
}

// ////////////////////////////////////////////////////////////////////////////
uint8_t KLineAddCs(KLineMessage *const pM) {
  const size_t pktSize = getPacketSize(pM);
  KLineMessageFtr *pFtr = (KLineMessageFtr *)getFtr(pM);
  pFtr->cs = calcCs(&pM->hdr.addr, pktSize-1);
  return pFtr->cs;
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocMessage(
  const uint8_t addr,
  const uint8_t func,
  const size_t payloadSize, 
  void *pPayloadCanBeNull) 
{
  const size_t sz = PACKET_SIZE(payloadSize);
  KLineMessage * const pM = Malloc(sz);
  memset(pM, 0, sz);
  pM->hdr.addr = addr;
  pM->hdr.function = func;
  pM->hdr.length = 1 + (uint8_t)payloadSize + 1;
  if (payloadSize > 0) {
    if (pPayloadCanBeNull) {
      memcpy(pM->u.payload, pPayloadCanBeNull, payloadSize);
    }
    else {
      memset(pM->u.payload, 0, payloadSize);
    }
  }
  
  if (pPayloadCanBeNull || (0 == payloadSize)) {
    KLineAddCs(pM);
    ASSERT(0 == KLineCheckCs(pM));
  }
  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
void KLineFreeMessage(KLineMessage *pM) {
  Free(pM);
}

// ////////////////////////////////////////////////////////////////////////////
static void KLineInitKey(
  KLineAuthTxRx *pAuth,
  const uint8_t * const pKey
  )
{

  const mbedtls_cipher_info_t * const pCInfo = 
    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  ASSERT(NULL != pCInfo);
  mbedtls_cipher_init(&pAuth->cmac);

  int stat = mbedtls_cipher_setup(&pAuth->cmac, pCInfo);
  ASSERT(0 == stat);

  stat = mbedtls_cipher_cmac_starts(&pAuth->cmac, pKey, SK_BYTES * 8);
  ASSERT(0 == stat);

  // Finish and reset, so can be started again without referring to key.
  uint8_t tmp[16 + 1] = { 0 }; // plus one senty byte
  stat = mbedtls_cipher_cmac_finish(&pAuth->cmac, tmp);
  ASSERT(0 == stat);
  ASSERT(0 == tmp[16]);
  stat = mbedtls_cipher_cmac_reset(&pAuth->cmac);
  ASSERT(0 == stat);

}

// ////////////////////////////////////////////////////////////////////////////
void KLineAuthDestruct(
  KLineAuth * const pThis
)
{
  mbedtls_cipher_free( &pThis->authRx.cmac );
  mbedtls_cipher_free( &pThis->authTx.cmac );
}

// ////////////////////////////////////////////////////////////////////////////
static void KLineAuthPair(
  KLineAuth * const pThis,
  bool isPakm,
  const KLinePairing * const pPairing)
{
  const uint8_t * const pTxKey = (isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  KLineInitKey(&pThis->authTx, pTxKey);

  const uint8_t * const pRxKey = (!isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  KLineInitKey(&pThis->authRx, pRxKey);
}

// ////////////////////////////////////////////////////////////////////////////
void KLineAuthInit(
  KLineAuth * const pThis
)
{
  uint8_t key[16];
  memset(pThis, 0, sizeof(KLineAuth));
  
  // Randomize the keys.
  defaultrandombytesFn(NULL, key, SK_BYTES);
  KLineInitKey(&pThis->authRx, key);
  defaultrandombytesFn(NULL, key, SK_BYTES);
  KLineInitKey(&pThis->authTx, key);

  // Randomize the tx and rx nonces
  defaultrandombytesFn(NULL, pThis->authTx.nonce.entireNonce.byteArray, sizeof(&pThis->authTx.nonce.entireNonce.byteArray));
  defaultrandombytesFn(NULL, pThis->authRx.nonce.entireNonce.byteArray, sizeof(&pThis->authRx.nonce.entireNonce.byteArray));
  
  // Set rxcnt to 255, next message will fail.
  pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt = 255;
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the PAKM side
void KLineAuthPairPAKM(
  KLineAuth * const pThis,
  const KLinePairing *pPairing) {
  KLineAuthPair(pThis, true, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the CEM side
void KLineAuthPairCEM(
  KLineAuth * const pThis,
  const KLinePairing *pPairing) {
  KLineAuthPair(pThis, false, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreateChallenge(
  const uint8_t addr,
  const uint8_t func,
  RandombytesFnPtr randFn,
  void *randFnData,
  const size_t challengeLenBits
)
{
  KLineChallenge challenge = { 0 };

  ASSERT(0 == challengeLenBits % 8);
  const size_t challengeLen = (challengeLenBits >= 32) ? challengeLenBits / 8 : 120 / 8;
  const size_t cpyBytes = MIN(challengeLen, sizeof(challenge.challenge120));
  ASSERT(cpyBytes >= 4);

  RandombytesFnPtr rndFn = (randFn) ? randFn : defaultrandombytesFn;
  rndFn(randFnData, challenge.challenge120, cpyBytes);
  return KLineAllocMessage(addr, func, cpyBytes, &challenge);
}

// ////////////////////////////////////////////////////////////////////////////
void KLineAuthChallenge(
  KLineAuth * const pThis,
  const KLineChallenge *txChallenge,
  const KLineChallenge *rxChallenge,
  const size_t challengeLenBits
) {
  ASSERT(0 == challengeLenBits % 8);
  const size_t challengeLen = (challengeLenBits >= 32) ? challengeLenBits / 8 : 120 / 8;
  const size_t cpyBytes = MIN(challengeLen, sizeof(txChallenge->challenge120));
  ASSERT(cpyBytes >= 4);

  // Zeroes at end of challenge if less than 120 bits are used.
  const size_t padBytes = sizeof(txChallenge->challenge120) - cpyBytes;

  if (txChallenge) {
    // Next sent message will use nonce of 0
    pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt = 1;
    memcpy(&pThis->authTx.nonce.txNoncePlusChallenge.challenge.challenge120[0], txChallenge, cpyBytes);
    memset(&pThis->authTx.nonce.txNoncePlusChallenge.challenge.challenge120[cpyBytes], 0, padBytes);
  }

  if (rxChallenge) {
    // Receiver believes its last received message is 0.
    pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt = 0;
    memcpy(&pThis->authRx.nonce.rxNoncePlusChallenge.challenge.challenge120[0], rxChallenge, cpyBytes);
    memset(&pThis->authRx.nonce.rxNoncePlusChallenge.challenge.challenge120[cpyBytes], 0, padBytes);
  }
}



// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreatePairing(
  const uint8_t addr,
  const uint8_t func,
  RandombytesFnPtr randFn,
  void *randFnData
)
{
  RandombytesFnPtr rndFn = (randFn) ? randFn : defaultrandombytesFn;
  KLinePairing pairing;
  rndFn(randFnData, pairing.cemToPak, sizeof(pairing.cemToPak));
  rndFn(randFnData, pairing.pakToCem, sizeof(pairing.pakToCem));
  return KLineAllocMessage(addr, func, sizeof(pairing), &pairing);
}

// ////////////////////////////////////////////////////////////////////////////
static int cmacTag(
  KLineAuthTxRx * const pAuth,
  const KLineAuthMessage * const pMsg,
  uint8_t tag[SIGNATURE_BYTES]
  ) {

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
  uint8_t tagTmp[16 + 1] = { 0 }; // plus one sentry byte
  stat = mbedtls_cipher_cmac_finish(&pAuth->cmac, tagTmp);
  ASSERT(0 == stat);
  ASSERT(0 == tagTmp[sizeof(tagTmp) - 1]);

  // Use only 8 bytes of signature.
  memcpy(tag, tagTmp, SIGNATURE_BYTES);

  return stat;
}


#define AUTH_SCMD_KLINE_PAYLOAD_SZ(spayloadbytes) \
  (sizeof(KLineAuthMessageHdr) + 1 + (spayloadbytes) + SIGNATURE_BYTES) // txcnt + sdata_len + scmd + spayload + tag

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreateAuthenticatedMessage(
  KLineAuth * const pThis,
  const uint8_t addr,
  const uint8_t func,
  const uint8_t scmd,
  const void *sPayloadPtr,
  const size_t sPayloadBytes
) {
  
  // Calculate the size of the data which will be signed.
  const size_t SDATA_LEN = 1 + sPayloadBytes; // scmd + sPayloadBytes;
  const size_t AUTH_SCMD_PAYLOAD_SZ = AUTH_SCMD_KLINE_PAYLOAD_SZ(sPayloadBytes);

  KLineMessage * const pM = KLineAllocMessage(addr, func, AUTH_SCMD_PAYLOAD_SZ, NULL);
  ASSERT(pM);

  // Set up headers and scmd
  pM->u.auth.hdr.txcnt = pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt;
  pM->u.auth.hdr.sdata_len = (uint8_t)SDATA_LEN; 
  pM->u.auth.sdata.u.sdata.scmd = scmd;

  // Copy the signed payload
  memcpy(pM->u.auth.sdata.u.sdata.spayload, sPayloadPtr, sPayloadBytes);

  // Get pointer to ciphertext out and the signature out
  uint8_t * const tag = &pM->u.auth.sdata.u.sdata.spayload[sPayloadBytes];
  
  const int stat = cmacTag(&pThis->authTx, &pM->u.auth, tag);
  ASSERT(0 == stat);

  KLineAddCs(pM);
  ASSERT(0 == KLineCheckCs(pM));

  ++pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt;
  ASSERT(0 != pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt);
  
  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
bool KLineAuthenticateMessage(
  KLineAuth * const pThis,
  const KLineMessage * const pMsgIn,
  const KLineAuthMessage **ppSigned ///< outputs the signed part of the incoming data    
) {
  bool rval = false;
  ASSERT(pMsgIn);
  if (0 == KLineCheckCs(pMsgIn)) {
    const size_t totalPacketSize = getPacketSize(pMsgIn);

    // Check that received message is after last received message.
    const int messagesLost = pMsgIn->u.auth.hdr.txcnt - pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt - 1;
    if ((messagesLost >= 0) && (messagesLost <= MAX_MISSED_MESSAGES)) {

      pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt = pMsgIn->u.auth.hdr.txcnt;

      const size_t sPayloadBytes = pMsgIn->u.auth.hdr.sdata_len - 1; // spayload

      const uint8_t * const tag = &pMsgIn->u.auth.sdata.u.sdata.spayload[sPayloadBytes];

      uint8_t tagTmp[SIGNATURE_BYTES] = { 0 };
      int stat = cmacTag(&pThis->authRx, &pMsgIn->u.auth, tagTmp);
      ASSERT(0 == stat);
      if (0 == stat) {
        stat = memcmp(tag, tagTmp, SIGNATURE_BYTES);
        ASSERT_WARN(0 == stat);
      }

      // Output variables
      if (0 == stat) {
        rval = true;
        if ((sPayloadBytes > 0) && (ppSigned)) {
          *ppSigned = &pMsgIn->u.auth;
        }
      }
    }
  }

  return rval;
}

// ////////////////////////////////////////////////////////////////////////////
// Gets the current TXCNT (next message)
uint8_t KLineAuthGetTxCnt(
  KLineAuth * const pThis
) {
  return pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt;
}

// ////////////////////////////////////////////////////////////////////////////
// Gets the current RXCNT (last received message.)
uint8_t KLineAuthGetRxCnt(
  KLineAuth * const pThis
) {
  return pThis->authRx.nonce.rxNoncePlusChallenge.rx_cnt;
}

// ////////////////////////////////////////////////////////////////////////////
// Sets TX count, for test purposes.
void KLineAuthSetTxCnt(
  KLineAuth * const pThis,
  const uint8_t txcnt
) {
  pThis->authTx.nonce.txNoncePlusChallenge.tx_cnt = txcnt;
}

