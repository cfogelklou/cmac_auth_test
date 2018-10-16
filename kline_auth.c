
#include "kline_auth.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef MIN
#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#endif

#ifdef __cplusplus
extern "C" {
#endif

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
#define KPKT_SIZE(payloadSize) \
  sizeof(KLineMessageHdr) + (payloadSize) + sizeof(KLineMessageFtr)

// ////////////////////////////////////////////////////////////////////////////
void *Malloc(const size_t sz) {
  void *p = malloc(sz);
  assert(p);
  return p;
}

// ////////////////////////////////////////////////////////////////////////////
void Free(void *pMem) {
  assert(pMem);
  free(pMem);
}

// ////////////////////////////////////////////////////////////////////////////
static size_t getPacketSize(const KLineMessage * const pM) {
  return pM->hdr.length + sizeof(pM->hdr.addr) + sizeof(pM->hdr.length);
}

// ////////////////////////////////////////////////////////////////////////////
static KLineMessageFtr *getFtr(KLineMessage * const pM) {
  const size_t len = getPacketSize(pM);
  uint8_t *p0 = &pM->hdr.addr;
  uint8_t *pFtr = &p0[len - 1];
  return (KLineMessageFtr *)pFtr;
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
int KLineCheckCs(KLineMessage * const pM) {
  const uint8_t cs0 = calcCs(&pM->hdr.addr, getPacketSize(pM) - 1);
  const KLineMessageFtr * pFtr = getFtr(pM);
  return pFtr->cs - cs0;
}

// ////////////////////////////////////////////////////////////////////////////
uint8_t KLineAddCs(KLineMessage *const pM) {
  const size_t pktSize = getPacketSize(pM);
  KLineMessageFtr *pFtr = getFtr(pM);
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
  const size_t sz = KPKT_SIZE(payloadSize);
  KLineMessage *pM = Malloc(sz);
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
  KLineAddCs(pM);

  assert(0 == KLineCheckCs(pM));
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
#ifdef KLINE_CCM
  mbedtls_ccm_init(&pAuth->ccm);
  int stat = mbedtls_ccm_setkey(&pAuth->ccm, MBEDTLS_CIPHER_ID_AES, pKey, 128);
  assert(stat == 0);

#else
  uint8_t tmp[16];
  const mbedtls_cipher_info_t *pCInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  assert(NULL != pCInfo);
  mbedtls_cipher_init(&pAuth->cmac);

  int stat = mbedtls_cipher_setup(&pAuth->cmac, pCInfo);
  assert(0 == stat);

  stat = mbedtls_cipher_cmac_starts(&pAuth->cmac, pKey, 16 * 8);
  assert(0 == stat);

  // Finish and reset, so can be started again without referring to key.
  stat = mbedtls_cipher_cmac_finish(&pAuth->cmac, tmp);
  assert(0 == stat);
  stat = mbedtls_cipher_cmac_reset(&pAuth->cmac);
  assert(0 == stat);

#endif
}

// ////////////////////////////////////////////////////////////////////////////
static void KLineAuthPair(
  KLineAuth *pThis,
  bool isPakm,
  const KLinePairing * const pPairing)
{
  const uint8_t * const pTxKey = (isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  KLineInitKey(&pThis->authTx, pTxKey);

  const uint8_t * const pRxKey = (!isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  KLineInitKey(&pThis->authRx, pRxKey);
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the PAKM side
void KLineAuthPairPAKM(
  KLineAuth *pThis,
  const KLinePairing *pPairing) {
  memset(pThis, 0, sizeof(KLineAuth));
  KLineAuthPair(pThis, true, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the CEM side
void KLineAuthPairCEM(
  KLineAuth *pThis,
  const KLinePairing *pPairing) {
  memset(pThis, 0, sizeof(KLineAuth));
  KLineAuthPair(pThis, false, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
void KLineAuthChallenge(
  KLineAuth * const pThis,
  const KLineChallenge txChallenge[15],
  const KLineChallenge rxChallenge[15]
) {
  if (txChallenge) {
    pThis->authTx.noncePlusCnt[0] = 1;
    memcpy(&pThis->authTx.noncePlusCnt[1], txChallenge, 15);
  }

  if (rxChallenge) {
    pThis->authRx.noncePlusCnt[0] = 0;
    memcpy(&pThis->authRx.noncePlusCnt[1], rxChallenge, 15);
  }
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreateChallenge(
  KLineAuth *pThis,
  const uint8_t addr,
  const uint8_t func,
  RandombytesFnPtr randFn,
  void *randFnData
)
{
  RandombytesFnPtr rndFn = (randFn) ? randFn : defaultrandombytesFn;
  KLineChallenge challenge;
  rndFn(randFnData, challenge.challenge, sizeof(challenge.challenge));
  return KLineAllocMessage(addr, func, sizeof(challenge), &challenge);
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreatePairing(
  KLineAuth *pThis,
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

#ifdef KLINE_CMAC
// ////////////////////////////////////////////////////////////////////////////
static int calcCmacTag(
  KLineAuthTxRx *pAuth,
  const uint8_t * pPayloadSigned,
  const size_t payloadSizeSigned,
  const uint8_t * pPlainText,
  const size_t plainTextSize,
  uint8_t tag[8]
  ) {
  const size_t nonceLen = sizeof(pAuth->noncePlusCnt);

  int stat = mbedtls_cipher_cmac_reset(&pAuth->cmac);
  assert(0 == stat);

  // CMAC over NONCE
  stat = mbedtls_cipher_cmac_update(
    &pAuth->cmac,
    pAuth->noncePlusCnt,
    sizeof(pAuth->noncePlusCnt));
  assert(0 == stat);

  // CMAC over signed data
  if ((pPayloadSigned) && (payloadSizeSigned > 0)) {
    stat = mbedtls_cipher_cmac_update(
      &pAuth->cmac,
      pPayloadSigned,
      payloadSizeSigned);
    assert(0 == stat);
  }

  // CMAC over encrypted data.
  if ((pPlainText) && (plainTextSize > 0)) {
    stat = mbedtls_cipher_cmac_update(
      &pAuth->cmac,
      pPlainText,
      plainTextSize);
    assert(0 == stat);
  }

  // TODO: Padding?

  uint8_t tagTmp[16 + 1] = { 0 };
  stat = mbedtls_cipher_cmac_finish(&pAuth->cmac, tagTmp);
  assert(0 == stat);
  assert(0 == tagTmp[sizeof(tagTmp) - 1]);
  memcpy(tag, tagTmp, 8);

  return stat;
}
#endif // #ifdef KLINE_CMAC

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocAuthenticatedMessage(
  KLineAuth *pThis,
  const uint8_t addr,
  const uint8_t func,
  const void *pPayloadSigned,
  const size_t payloadSizeSigned,
  const void *pPlainText,
  const size_t plainTextSize
) {
  size_t sz = KPKT_SIZE(0);
  sz += 1; // txcnt;
  sz += 1; // SCMD
  sz += payloadSizeSigned;
  sz += plainTextSize;
  sz += 8; // signature
  KLineMessage *pM = Malloc(sz);
  memset(pM, 0, sz);
  pM->hdr.addr = addr;
  pM->hdr.function = func;
  pM->hdr.length = (uint8_t)(sz - 1 - 1); // Size - sizeof(addr) - sizeof(length)
  KLineAuthMessage *pAead = (KLineAuthMessage *)pM->u.payload;
  pAead->hdr.txcnt = pThis->authTx.noncePlusCnt[0];
  pAead->hdr.sdata_len = (uint8_t)payloadSizeSigned;
  memcpy(&pAead->sdata_and_edata[0], pPayloadSigned, payloadSizeSigned);
  uint8_t * const pCipherText = &pAead->sdata_and_edata[payloadSizeSigned];
  uint8_t * const tag = &pAead->sdata_and_edata[payloadSizeSigned + plainTextSize];
  
  {
#ifdef KLINE_CCM
    // Include TXCNT in the signed data.
    const size_t addlDataSize = 1 + payloadSizeSigned;
    uint8_t *pAddl = Malloc(addlDataSize);
    pAddl[0] = pAead->hdr.txcnt;
    memcpy(&pAddl[1], pPayloadSigned, payloadSizeSigned);

    const size_t nonceLen = MIN(sizeof(pThis->authTx.noncePlusCnt), 13);

    const int stat = mbedtls_ccm_encrypt_and_tag(
      &pThis->authTx.ccm, //ctx
      plainTextSize, //length
      pThis->authTx.noncePlusCnt, //iv
      nonceLen, //iv_len
      pAddl, // add
      addlDataSize, // add_len
      pPlainText, // input
      pCipherText, //output
      tag, 8);  //tag, tag_len

    Free(pAddl);

#else    

    // CMAC has no encryption; copy plaintext to ciphertext.
    if ((pPlainText) && (plainTextSize > 0)) {
      memcpy(pCipherText, pPlainText, plainTextSize);
    }

    const int stat = 
      calcCmacTag(&pThis->authTx, pPayloadSigned, payloadSizeSigned, pPlainText, plainTextSize, tag);

#endif
    assert(0 == stat);
  }

  KLineAddCs(pM);

  assert(0 == KLineCheckCs(pM));

  ++pThis->authTx.noncePlusCnt[0];
  assert(0 != pThis->authTx.noncePlusCnt[0]);
  return pM;
}


// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocDecryptMessage(
  KLineAuth *pThis,
  const KLineMessage * const pEncryptedMsg,
  const uint8_t **ppSigned,
  size_t *pSignedLen,
  const uint8_t **ppPlainText,
  size_t *pPlainTextLen
) {

  KLineMessage *pM = NULL;
  if (0 == KLineCheckCs(pEncryptedMsg)) {
    const size_t totalPacketSize = getPacketSize(pEncryptedMsg);
    const KLineAuthMessage * const pAeadIn = &pEncryptedMsg->u.aead;
    const int diff = pAeadIn->hdr.txcnt - pThis->authRx.noncePlusCnt[0];
    if (diff > 0) {
      pThis->authRx.noncePlusCnt[0] = pAeadIn->hdr.txcnt;
      pM = Malloc(totalPacketSize);

      // Make a copy of the encrypted packet, which we will overwrite.
      memcpy(pM, pEncryptedMsg, totalPacketSize);
      KLineAuthMessage * const pAeadOut = &pM->u.aead;
      const size_t payloadSizeSigned = pAeadIn->hdr.sdata_len;
      const uint8_t * pPayloadSigned = pAeadOut->sdata_and_edata;
      const uint8_t * pCipherText = &pAeadIn->sdata_and_edata[payloadSizeSigned];
      uint8_t * const pPlainText = &pAeadOut->sdata_and_edata[payloadSizeSigned];
      const size_t cipherTextSize =
        totalPacketSize
        - 2 // addr + length
        - 1 // function
        - 1 // txcnt
        - 1 // scmd
        - 1 - payloadSizeSigned // sdatalen - payloadSize
        - 8; // signature
      const size_t plainTextSize = cipherTextSize;

      if (cipherTextSize > 0) {
        memset(pPlainText, 0, cipherTextSize);
      }

      const uint8_t * const tag = &pAeadIn->sdata_and_edata[payloadSizeSigned + cipherTextSize];

      {
#ifdef KLINE_CCM
        // Include TXCNT in the signed data.
        const size_t addlDataSize = 1 + payloadSizeSigned;
        uint8_t *pAddl = Malloc(addlDataSize);
        pAddl[0] = pAeadIn->hdr.txcnt;
        if (payloadSizeSigned > 0) {
          memcpy(&pAddl[1], pPayloadSigned, payloadSizeSigned);
        }

        const size_t nonceLen = MIN(sizeof(pThis->authRx.noncePlusCnt), 13);


        const int stat = mbedtls_ccm_auth_decrypt(
          &pThis->authRx.ccm, // ctx
          cipherTextSize, // length
          pThis->authRx.noncePlusCnt, // iv
          nonceLen, // iv_len
          pAddl, // add
          addlDataSize, // add_len
          pCipherText, // input
          pPlainText, // output
          tag, 8 // tag, tag_len
        );

        Free(pAddl);
        assert(0 == stat);
#else
        // CMAC has no encryption; copy ciphertext to plaintext
        if (cipherTextSize > 0) {
          memcpy(pPlainText, pCipherText, cipherTextSize);
        }

        uint8_t tagTmp[8] = { 0 };
        int stat =
          calcCmacTag(&pThis->authRx, pPayloadSigned, payloadSizeSigned, pPlainText, plainTextSize, tagTmp);
        assert(0 == stat);

        stat = memcmp(tag, tagTmp, 8);
        assert(0 == stat);
#endif

        // Output variables
        if (0 == stat) {
          if ((cipherTextSize > 0) && (ppPlainText)) {
            *ppPlainText = pPlainText;
          }
          if (pPlainTextLen) {
            *pPlainTextLen = cipherTextSize;
          }
          if ((payloadSizeSigned > 0) && (ppSigned)) {
            *ppSigned = pAeadOut->sdata_and_edata;
          }
          if (pSignedLen) {
            *pSignedLen = payloadSizeSigned;
          }
        }
      }
    }
  }
  Free(pEncryptedMsg);
  return pM;
}

#ifdef __cplusplus
}
#endif
