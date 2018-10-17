
#include "kline_auth.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // for NULL

#ifndef MIN
#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#endif

#ifdef __cplusplus
extern "C" {
#endif

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
  
  if (pPayloadCanBeNull) {
    KLineAddCs(pM);
    assert(0 == KLineCheckCs(pM));
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
#ifdef KLINE_CCM
  mbedtls_ccm_init(&pAuth->ccm);
  int stat = mbedtls_ccm_setkey(&pAuth->ccm, MBEDTLS_CIPHER_ID_AES, pKey, 128);
  assert(stat == 0);

#else
  uint8_t tmp[16];
  const mbedtls_cipher_info_t * const pCInfo = 
    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
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
void KLineAuthDestruct(
  KLineAuth * const pThis
)
{
#ifdef KLINE_CCM
  mbedtls_ccm_free(&pThis->authRx.ccm);
  mbedtls_ccm_free(&pThis->authTx.ccm);
#else
  mbedtls_cipher_free( &pThis->authRx.cmac );
  mbedtls_cipher_free( &pThis->authTx.cmac );
#endif
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
// Initialize the PAKM side
void KLineAuthPairPAKM(
  KLineAuth * const pThis,
  const KLinePairing *pPairing) {
  memset(pThis, 0, sizeof(KLineAuth));
  KLineAuthPair(pThis, true, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the CEM side
void KLineAuthPairCEM(
  KLineAuth * const pThis,
  const KLinePairing *pPairing) {
  memset(pThis, 0, sizeof(KLineAuth));
  KLineAuthPair(pThis, false, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
void KLineAuthChallenge(
  KLineAuth * const pThis,
  const KLineChallenge *txChallenge,
  const KLineChallenge *rxChallenge
) {
  if (txChallenge) {
    // Next sent message will use nonce of 0
    pThis->authTx.nonce.noncePlusChallenge.tx_cnt = 1;
    memcpy(&pThis->authTx.nonce.noncePlusChallenge.challenge.challenge120, txChallenge, sizeof(KLineChallenge));
  }

  if (rxChallenge) {
    // Receiver believes its last received message is 0.
    pThis->authRx.nonce.noncePlusChallenge.tx_cnt = 0;
    memcpy(&pThis->authRx.nonce.noncePlusChallenge.challenge.challenge120, rxChallenge, sizeof(KLineChallenge));
  }
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreateChallenge(
  KLineAuth * const pThis,
  const uint8_t addr,
  const uint8_t func,
  RandombytesFnPtr randFn,
  void *randFnData
)
{
  RandombytesFnPtr rndFn = (randFn) ? randFn : defaultrandombytesFn;
  KLineChallenge challenge;
  rndFn(randFnData, challenge.challenge120, sizeof(challenge.challenge120));
  return KLineAllocMessage(addr, func, sizeof(challenge), &challenge);
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreatePairing(
  KLineAuth * const pThis,
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
  const uint8_t * sDataPtr,
  const size_t sPayloadBytes,
  const uint8_t * ePayloadPlainTextPtr,
  const size_t ePayloadBytes,
  uint8_t tag[8]
  ) {
  const size_t nonceLen = sizeof(pAuth->nonce);

  int stat = mbedtls_cipher_cmac_reset(&pAuth->cmac);
  assert(0 == stat);

  // CMAC over NONCE
  stat = mbedtls_cipher_cmac_update(
    &pAuth->cmac,
    pAuth->nonce.iv.iv,
    sizeof(pAuth->nonce.iv.iv));
  assert(0 == stat);

  // CMAC over signed data
  if ((sDataPtr) && (sPayloadBytes > 0)) {
    stat = mbedtls_cipher_cmac_update(
      &pAuth->cmac,
      sDataPtr,
      sPayloadBytes);
    assert(0 == stat);
  }

  // CMAC over encrypted data.
  if ((ePayloadPlainTextPtr) && (ePayloadBytes > 0)) {
    stat = mbedtls_cipher_cmac_update(
      &pAuth->cmac,
      ePayloadPlainTextPtr,
      ePayloadBytes);
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

typedef struct AdditionalDataTag {
  uint8_t tx_cnt;
  uint8_t scmd;
  uint8_t spayload[1];
}AdditionalData;

#define AUTH_SCMD_KLINE_PAYLOAD_SZ(spayloadbytes, epayloadbytes) \
  (sizeof(KLineAuthMessageHdr) + 1 + (spayloadbytes) + (epayloadbytes) + 8)

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocAuthenticatedMessage(
  KLineAuth * const pThis,
  const uint8_t addr,
  const uint8_t func,
  const uint8_t scmd,
  const void *sPayloadPtr,
  const size_t sPayloadBytes,
  const void *ePayloadPlainTextPtr,
  const size_t ePayloadBytes
) {
  
  // Calculate the size of the data which will be signed.
  const size_t SDATA_LEN = 1 + sPayloadBytes; // scmd + sPayloadBytes;
  const size_t AUTH_SCMD_PAYLOAD_SZ = AUTH_SCMD_KLINE_PAYLOAD_SZ(sPayloadBytes, ePayloadBytes);

  KLineMessage * const pM = KLineAllocMessage(addr, func, AUTH_SCMD_PAYLOAD_SZ, NULL);

  // Set up headers and scmd
  pM->u.aead.hdr.txcnt = pThis->authTx.nonce.noncePlusChallenge.tx_cnt;
  pM->u.aead.hdr.sdata_len = (uint8_t)SDATA_LEN; 
  pM->u.aead.sdata.u.sdata.scmd = scmd;

  // Copy the signed payload
  memcpy(pM->u.aead.sdata.u.sdata.spayload_and_edata, sPayloadPtr, sPayloadBytes);

  // Get pointer to ciphertext out and the signature out
  uint8_t * const ePayloadCipherTextPtr = &pM->u.aead.sdata.u.sdata.spayload_and_edata[sPayloadBytes];
  uint8_t * const tag = &pM->u.aead.sdata.u.sdata.spayload_and_edata[sPayloadBytes + ePayloadBytes];
  
  {
#ifdef KLINE_CCM
    // Include TXCNT in the signed data, as specified in the document
    const size_t addlDataSize = 1 + 1 + sPayloadBytes; // tx_cnt + scmd + spayload
    AdditionalData * const pAddlData = (AdditionalData *)Malloc(addlDataSize);
    pAddlData->tx_cnt = pM->u.aead.hdr.txcnt;
    pAddlData->scmd = pM->u.aead.sdata.u.sdata.scmd;
    memcpy(pAddlData->spayload, pM->u.aead.sdata.u.sdata.spayload_and_edata, sPayloadBytes);

    const size_t nonceLen = MIN(sizeof(pThis->authTx.nonce), 13);

    const int stat = mbedtls_ccm_encrypt_and_tag(
      &pThis->authTx.ccm, //ctx
      ePayloadBytes, //length (of ciphertext)
      pThis->authTx.nonce.iv.iv, //iv
      nonceLen, //iv_len
      &pAddlData->tx_cnt, // add (additional data)
      addlDataSize, // add_len (length of additional data)
      ePayloadPlainTextPtr, // input (plain text)
      ePayloadCipherTextPtr, //output (cipher text)
      tag, 8);  //tag, tag_len

    Free(pAddlData);
#else    

    // CMAC has no encryption; copy plaintext to ciphertext.
    if ((ePayloadPlainTextPtr) && (ePayloadBytes > 0)) {
      memcpy(ePayloadCipherTextPtr, ePayloadPlainTextPtr, ePayloadBytes);
    }

    const int stat = 
      calcCmacTag(&pThis->authTx, sPayloadPtr, sPayloadBytes, ePayloadPlainTextPtr, ePayloadBytes, tag);

#endif
    assert(0 == stat);
  }

  KLineAddCs(pM);

  assert(0 == KLineCheckCs(pM));

  ++pThis->authTx.nonce.noncePlusChallenge.tx_cnt;
  assert(0 != pThis->authTx.nonce.noncePlusChallenge.tx_cnt);
  
  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocDecryptMessage(
  KLineAuth * const pThis,
  const KLineMessage * const pMsgIn,
  const KLineAuthMessage **ppSigned, ///< outputs the signed part of the incoming data    
  const uint8_t **ppEPayloadPlainText, ///< outputs the decrypted part of the incoming data.
  size_t *pEPayloadPlainText ///< outputs the length of the plaintext
) {

  KLineMessage *pMsgOut = NULL;
  if (0 == KLineCheckCs(pMsgIn)) {
    const size_t totalPacketSize = getPacketSize(pMsgIn);

    // Check that received message is after last received message.
    const int diff = pMsgIn->u.aead.hdr.txcnt - pThis->authRx.nonce.noncePlusChallenge.tx_cnt;
    if (diff > 0) {

      pThis->authRx.nonce.noncePlusChallenge.tx_cnt = pMsgIn->u.aead.hdr.txcnt;
      pMsgOut = Malloc(totalPacketSize);

      // Make a copy of the encrypted packet, which we will overwrite.
      memcpy(pMsgOut, pMsgIn, totalPacketSize);

      const size_t sPayloadBytes = pMsgIn->u.aead.hdr.sdata_len - 1; // spayload
      const size_t sDataBytes = pMsgIn->u.aead.hdr.sdata_len; // scmd + spayload

      const uint8_t * pCipherText = &pMsgIn->u.aead.sdata.u.sdata.spayload_and_edata[sPayloadBytes];
      uint8_t * const pPlainText = &pMsgOut->u.aead.sdata.u.sdata.spayload_and_edata[sPayloadBytes];

      const size_t cipherTextSize =
        totalPacketSize
        - sizeof(KLineMessageHdr) // addr + length
        - sizeof(KLineAuthMessageHdr) // txcnt + sdata_len
        - sDataBytes // scmd + spayload
        - 8 // signature
        - sizeof(KLineMessageFtr); // cs
      const size_t ePayloadBytes = cipherTextSize;

      if (cipherTextSize > 0) {
        memset(pPlainText, 0, cipherTextSize);
      }

      const uint8_t * const tag = &pMsgIn->u.aead.sdata.u.sdata.spayload_and_edata[sPayloadBytes + cipherTextSize];

      {
#ifdef KLINE_CCM
        // Include TXCNT in the signed data.
        const size_t addlDataSize = 1 + 1 + sPayloadBytes; // tx_cnt + scmd + spayload
        AdditionalData * const pAddlData = (AdditionalData *)Malloc(addlDataSize);
        pAddlData->tx_cnt = pMsgIn->u.aead.hdr.txcnt;
        pAddlData->scmd = pMsgIn->u.aead.sdata.u.sdata.scmd;
        if (sPayloadBytes > 0) {
          memcpy(pAddlData->spayload, pMsgOut->u.aead.sdata.u.sdata.spayload_and_edata, sPayloadBytes);
        }

        const size_t nonceLen = MIN(sizeof(pThis->authRx.nonce), 13);

        const int stat = mbedtls_ccm_auth_decrypt(
          &pThis->authRx.ccm, // ctx
          cipherTextSize, // length
          pThis->authRx.nonce.iv.iv, // iv
          nonceLen, // iv_len
          &pAddlData->tx_cnt, // add
          addlDataSize, // add_len
          pCipherText, // input
          pPlainText, // output
          tag, 8 // tag, tag_len
        );

        Free(pAddlData);
        assert(0 == stat);
#else
        // CMAC has no encryption; copy ciphertext to plaintext
        if (cipherTextSize > 0) {
          memcpy(pPlainText, pCipherText, cipherTextSize);
        }

        uint8_t tagTmp[8] = { 0 };
        int stat =
          calcCmacTag(&pThis->authRx, sDataPtr, sPayloadBytes, pPlainText, ePayloadBytes, tagTmp);
        assert(0 == stat);

        stat = memcmp(tag, tagTmp, 8);
        assert(0 == stat);
#endif

        // Output variables
        if (0 == stat) {
          if ((cipherTextSize > 0) && (ppEPayloadPlainText)) {
            *ppEPayloadPlainText = pPlainText;
          }
          if (pEPayloadPlainText) {
            *pEPayloadPlainText = cipherTextSize;
          }
          if ((sPayloadBytes > 0) && (ppSigned)) {
            *ppSigned = &pMsgOut->u.aead;
          }
        }
      }
    }
  }
  Free(pMsgIn);
  return pMsgOut;
}

#ifdef __cplusplus
}
#endif
