
#include "kline_ccm.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MIN(x,y) (((x) < (y)) ? (x) : (y))

#ifdef __cplusplus
//extern "C" {
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
  KLineMessage *pM = malloc(sz);
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
  free(pM);
}


static void printHex(
  const char * const prefix,
  const uint8_t *pHex, const size_t len, 
  const char * const postfix) {

  if (prefix) {
    printf(prefix);
  }

  for (size_t i = 0; i < len; i++) {
    printf("%02x", pHex[i]);
  }

  if (postfix) {
    printf(postfix);
  }
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocEncryptMessage(
  KLineCcm *pThis,
  const uint8_t addr,
  const uint8_t func,
  const void *pPayloadSigned,
  const size_t payloadSizeSigned,
  const void *pPlainText,
  const size_t plainTextSize,
  KLineCcm *pRx
) {
  size_t sz = KPKT_SIZE(0);
  sz += 1; // txcnt;
  sz += 1; // SCMD
  sz += payloadSizeSigned;
  sz += plainTextSize;
  sz += 8; // signature
  KLineMessage *pM = malloc(sz);
  memset(pM, 0, sz);
  pM->hdr.addr = addr;
  pM->hdr.function = func;
  pM->hdr.length = sz - 1 - 1; // Size - sizeof(addr) - sizeof(length)
  KLineAEADMessage *pAead = (KLineAEADMessage *)pM->u.payload;
  pAead->hdr.txcnt = pThis->ccmTx.noncePlusCnt[0];
  pAead->hdr.sdata_len = payloadSizeSigned;
  memcpy(&pAead->sdata_and_edata[0], pPayloadSigned, payloadSizeSigned);
  uint8_t * const output = &pAead->sdata_and_edata[payloadSizeSigned];
  uint8_t * const tag = &pAead->sdata_and_edata[payloadSizeSigned + plainTextSize];

  {
    // Include TXCNT in the signed data.
    const size_t addlDataSize = 1 + payloadSizeSigned;
    uint8_t *pAddl = malloc(addlDataSize);
    pAddl[0] = pAead->hdr.txcnt;
    memcpy(&pAddl[1], pPayloadSigned, payloadSizeSigned);

    const size_t nonceLen = MIN(sizeof(pThis->ccmTx.noncePlusCnt), 13);

    printHex("enc:key ", pThis->ccmTx.key, sizeof(pThis->ccmTx.key), "\r\n");
    printf(  "enc:payloadSizeSigned:%x\r\n", payloadSizeSigned);
    printHex("enc:payloadSgn: ", pPayloadSigned, payloadSizeSigned, "\r\n");
    printf(  "enc:payloadSizeToEncrypt:%x\r\n", plainTextSize);
    printHex("enc:payloadEnc: ", pPlainText, plainTextSize, "\r\n");
    printHex("enc:noncePlusCnt:", pThis->ccmTx.noncePlusCnt, sizeof(pThis->ccmTx.noncePlusCnt), "\r\n");
    printf(  "enc:nonceLen:%d\r\n", nonceLen);
    printf(  "enc:addlDatasize:%d\r\n", addlDataSize);
    printHex("enc:pAddl:", pAddl, addlDataSize, "\r\n");

    const int stat = mbedtls_ccm_encrypt_and_tag(
      &pThis->ccmTx.ccm, //ctx
      plainTextSize, //length
      pThis->ccmTx.noncePlusCnt, //iv
      nonceLen, //iv_len
      pAddl, // add
      addlDataSize, // add_len
      pPlainText, // input
      output, //output
      tag, 8);  //tag, tag_len

    {
      
      //mbedtls_ccm_init(&pRx->ccmRx.ccm);
      //mbedtls_ccm_setkey(&pRx->ccmRx.ccm, MBEDTLS_CIPHER_ID_AES, pThis->ccmTx.key, sizeof(pThis->ccmTx.key) * 8);

      uint8_t *pTmp = malloc(plainTextSize);
      int s = mbedtls_ccm_auth_decrypt(
        &pRx->ccmRx.ccm, plainTextSize,
        pThis->ccmTx.noncePlusCnt, nonceLen, 
        pAddl, addlDataSize, 
        pPlainText, pTmp, 
        tag, 8);
      free(pTmp);

      assert(0 == s);

      //mbedtls_ccm_free(&t);
    }

    printHex("enc:encrypted:", output, plainTextSize, "\r\n");
    printHex("enc:tag:", tag, 8, "\r\n");

    assert(0 == stat);
  
    free(pAddl);
  }

  KLineAddCs(pM);

  assert(0 == KLineCheckCs(pM));

  ++pThis->ccmTx.noncePlusCnt[0];
  assert(0 != pThis->ccmTx.noncePlusCnt[0]);
  return pM;
}


// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineAllocDecryptMessage(
  KLineCcm *pThis,
  const KLineMessage * const pEncryptedMsg) {

  KLineMessage *pM = NULL;
  if (0 == KLineCheckCs(pEncryptedMsg)) {
    const size_t totalPacketSize = getPacketSize(pEncryptedMsg);
    const KLineAEADMessage * const pAeadIn = &pEncryptedMsg->u.aead;
    const int diff = pAeadIn->hdr.txcnt - pThis->ccmRx.noncePlusCnt[0];
    if (diff > 0) {
      pThis->ccmRx.noncePlusCnt[0] = pAeadIn->hdr.txcnt;
      pM = malloc(totalPacketSize);
      memcpy(pM, pEncryptedMsg, totalPacketSize);
      KLineAEADMessage * const pAeadOut = &pM->u.aead;
      const size_t payloadSizeSigned = pAeadIn->hdr.sdata_len;
      const uint8_t * pCipherText = &pAeadIn->sdata_and_edata[payloadSizeSigned];
      const uint8_t * pPlainText = &pAeadOut->sdata_and_edata[payloadSizeSigned];
      const size_t cipherTextSize =
        totalPacketSize
        - 2 // addr + length
        - 1 // function
        - 1 // txcnt
        - 1 // sdata_len
        - payloadSizeSigned - 1
        - 8; // signature

      if (cipherTextSize > 0) {
        memset(pPlainText, 0, sizeof(cipherTextSize));
      }
      const uint8_t * const tag = &pAeadIn->sdata_and_edata[payloadSizeSigned + cipherTextSize];

      {
        // Include TXCNT in the signed data.
        const size_t addlDataSize = 1 + payloadSizeSigned;
        // Include TXCNT in the signed data.
        uint8_t *pAddl = malloc(addlDataSize);
        pAddl[0] = pAeadIn->hdr.txcnt;
        if (payloadSizeSigned > 0) {
          memcpy(&pAddl[1], pAeadIn->sdata_and_edata, payloadSizeSigned);
        }

        const size_t nonceLen = MIN(sizeof(pThis->ccmRx.noncePlusCnt), 13);

        printf("\r\n");
        printHex("dec:key ", pThis->ccmRx.key, sizeof(pThis->ccmRx.key), "\r\n");
        printf("dec:payloadSizeSigned:%x\r\n", payloadSizeSigned);
        printHex("dec:payloadSgn: ", pAeadIn->sdata_and_edata, payloadSizeSigned, "\r\n");
        printf("dec:payloadSizeEncrypted:%x\r\n", cipherTextSize);
        printHex("dec:encrypted: ", pCipherText, cipherTextSize, "\r\n");
        printHex("dec:noncePlusCnt:", pThis->ccmRx.noncePlusCnt, sizeof(pThis->ccmRx.noncePlusCnt), "\r\n");
        printf("dec:nonceLen:%d\r\n", nonceLen);
        printf("dec:addlDatasize:%d\r\n", addlDataSize);
        printHex("dec:pAddl:", pAddl, addlDataSize, "\r\n");
        printHex("dec:tag:", tag, 8, "\r\n");

        const int stat = mbedtls_ccm_auth_decrypt(
          &pThis->ccmRx.ccm, // ctx
          cipherTextSize, // length
          pThis->ccmRx.noncePlusCnt, // iv
          nonceLen, // iv_len
          pAddl, // add
          addlDataSize, // add_len
          pCipherText, // input
          pPlainText, // output
          tag, 8 // tag, tag_len
        );

        printHex("enc:decrypted:", pPlainText, cipherTextSize, "\r\n");


        assert(0 == stat);

        free(pAddl);
      }

    }
  }
  free(pEncryptedMsg);
  return pM;
}

// ////////////////////////////////////////////////////////////////////////////
static void KLineCcmInit(
  KLineCcm *pThis,
  bool isPakm,
  const KLinePairing * const pPairing)
{

  mbedtls_ccm_init(&pThis->ccmTx.ccm);
  mbedtls_ccm_init(&pThis->ccmRx.ccm);

  const uint8_t * const pTxKey = (isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  const uint8_t * const pRxKey = (!isPakm) ? pPairing->pakToCem : pPairing->cemToPak;
  memcpy(pThis->ccmTx.key, pTxKey, 16);
  int stat = mbedtls_ccm_setkey(&pThis->ccmTx.ccm, MBEDTLS_CIPHER_ID_AES, pTxKey, 128);
  assert(stat == 0);

  memcpy(pThis->ccmRx.key, pRxKey, 16);
  stat = mbedtls_ccm_setkey(&pThis->ccmRx.ccm, MBEDTLS_CIPHER_ID_AES, pRxKey, 128);
  assert(stat == 0);


}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the PAKM side
void KLineCcmInitPAKM(
  KLineCcm *pThis,
  const KLinePairing *pPairing) {
  memset(pThis, 0, sizeof(KLineCcm));
  KLineCcmInit(pThis, true, pPairing);
}

// ////////////////////////////////////////////////////////////////////////////
// Initialize the CEM side
void KLineCcmInitCEM(
  KLineCcm *pThis,
  const KLinePairing *pPairing) {
  memset(pThis, 0, sizeof(KLineCcm));
  KLineCcmInit(pThis, false, pPairing);
}


// ////////////////////////////////////////////////////////////////////////////
void KLineCcmChallenge(
  KLineCcm * const pThis,
  const KLineChallenge txChallenge[15],
  const KLineChallenge rxChallenge[15]
) {
  if (txChallenge) {
    pThis->ccmTx.noncePlusCnt[0] = 1;
    memcpy(&pThis->ccmTx.noncePlusCnt[1], txChallenge, 15);
  }

  if (rxChallenge) {
    pThis->ccmRx.noncePlusCnt[0] = 0;
    memcpy(&pThis->ccmRx.noncePlusCnt[1], rxChallenge, 15);
  }
}

// ////////////////////////////////////////////////////////////////////////////
// Use RAND() to generate challenge.
static void defaultrandombytesFn(void *p, uint8_t *pBuf, size_t bufLen) {
  (void)p;
  for (int i = 0; i < bufLen; i++) {
    pBuf[i] = rand() & 0xff;
  }
}

// ////////////////////////////////////////////////////////////////////////////
KLineMessage *KLineCreateChallenge(
  KLineCcm *pThis,
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
  KLineCcm *pThis,
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
//}
#endif
