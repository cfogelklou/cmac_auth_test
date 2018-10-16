
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
  void *pPayloadCanBeNull) {
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
KLineMessage *KLineAllocEncryptMessage(
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
  uint8_t * const output = &pAead->sdata_and_edata[payloadSizeSigned];
  uint8_t * const tag = &pAead->sdata_and_edata[payloadSizeSigned + plainTextSize];

  {
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
      output, //output
      tag, 8);  //tag, tag_len

    assert(0 == stat);
  
    Free(pAddl);
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
      memcpy(pM, pEncryptedMsg, totalPacketSize);
      KLineAuthMessage * const pAeadOut = &pM->u.aead;
      const size_t payloadSizeSigned = pAeadIn->hdr.sdata_len;
      const uint8_t * pCipherText = &pAeadIn->sdata_and_edata[payloadSizeSigned];
      uint8_t * pPlainText = &pAeadOut->sdata_and_edata[payloadSizeSigned];
      const size_t cipherTextSize =
        totalPacketSize
        - 2 // addr + length
        - 1 // function
        - 1 // txcnt
        - 1 // sdata_len
        - 1 - payloadSizeSigned // scmd - payloadSize
        - 8; // signature

      if (cipherTextSize > 0) {
        memset(pPlainText, 0, sizeof(cipherTextSize));
      }
      const uint8_t * const tag = &pAeadIn->sdata_and_edata[payloadSizeSigned + cipherTextSize];

      {
        // Include TXCNT in the signed data.
        const size_t addlDataSize = 1 + payloadSizeSigned;
        uint8_t *pAddl = Malloc(addlDataSize);
        pAddl[0] = pAeadIn->hdr.txcnt;
        if (payloadSizeSigned > 0) {
          memcpy(&pAddl[1], pAeadIn->sdata_and_edata, payloadSizeSigned);
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

        assert(0 == stat);

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

        Free(pAddl);
      }

    }
  }
  Free(pEncryptedMsg);
  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
static void KLineAuthPair(
  KLineAuth *pThis,
  bool isPakm,
  const KLinePairing * const pPairing)
{

  mbedtls_ccm_init(&pThis->authTx.ccm);
  const uint8_t * const pTxKey = (isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  int stat = mbedtls_ccm_setkey(&pThis->authTx.ccm, MBEDTLS_CIPHER_ID_AES, pTxKey, 128);
  assert(stat == 0);

  mbedtls_ccm_init(&pThis->authRx.ccm);
  const uint8_t * const pRxKey = (!isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  stat = mbedtls_ccm_setkey(&pThis->authRx.ccm, MBEDTLS_CIPHER_ID_AES, pRxKey, 128);
  assert(stat == 0);

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
// Use RAND() to generate challenge.
static void defaultrandombytesFn(void *p, uint8_t *pBuf, size_t bufLen) {
  (void)p;
  for (size_t i = 0; i < bufLen; i++) {
    pBuf[i] = rand() & 0xff;
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

#ifdef __cplusplus
}
#endif
