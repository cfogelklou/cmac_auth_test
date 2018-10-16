#ifndef KLINE_CCM_H__
#define KLINE_CCM_H__

#include "ccm.h"

#include <stdint.h>
#include <stdbool.h>
#include "packed.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#pragma warning(disable:4103)
#endif
#include "pack_push.h"


  typedef struct PACKED KLinePairingTag {
    uint8_t cemToPak[16];
    uint8_t pakToCem[16];
  } KLinePairing;

  typedef struct PACKED KLineChallengeTag{
    uint8_t challenge[120];
  } KLineChallenge;

  typedef struct PACKED KLineMessageHdrTag {
    uint8_t addr;
    uint8_t length;
    uint8_t function;    
  } KLineMessageHdr;
  
  typedef struct PACKED KLineMessageFtrTag {
    uint8_t cs;
  } KLineMessageFtr;

  typedef struct PACKED KLineAEADMessageHdrTag {
    uint8_t txcnt; // Least Significant Bits of 8-bit TXCNT part of message nonce.
    uint8_t sdata_len; // Specifies the length H, in bytes, of unencrypted, signed data preceding encrypted data. Also referred to as SPAYLOAD length.
  } KLineAEADMessageHdr;

  typedef struct PACKED KLineAEADMessageFtrTag {
    uint8_t sig[8];
  } KLineAEADMessageFtr;

  typedef struct PACKED KLineAEADMessageTag {
    KLineAEADMessageHdr hdr;
    uint8_t sdata_and_edata[1];
    uint8_t edata[1];
    KLineAEADMessageFtr ftr;
  } KLineAEADMessage;

  // Never use this object directly.
  typedef struct PACKED KLineMessageTag {
    KLineMessageHdr hdr;
    union {
      KLinePairing    pairing;
      KLineChallenge  challenge;
      KLineAEADMessage aead;
      uint8_t          payload[1];
    }u;
    KLineMessageFtr ftr;
  } KLineMessage;

#include "pack_pop.h"
#ifdef WIN32
#pragma warning(default:4103)
#endif

  // Allocates a non-encrypted message
  KLineMessage *KLineAllocMessage(
    const uint8_t addr,
    const uint8_t func,
    const size_t payloadSize, 
    void *pPayloadCanBeNull);

  // Frees a non-encrypted challenge
  void KLineFreeMessage(KLineMessage *pM);

  // Checks the CS on a message
  int KLineCheckCs(KLineMessage * const pM);

  // Adds the CS to a message.
  uint8_t KLineAddCs(KLineMessage * const pM);

  typedef struct KLineCcmTxTag {
    mbedtls_ccm_context ccm;
    uint8_t key[16];
    uint8_t noncePlusCnt[16];
  } KLineCcmTx;

  typedef struct KLineCcmRxTag {
    mbedtls_ccm_context ccm;
    uint8_t key[16];
    uint8_t noncePlusCnt[16];
  } KLineCcmRx;

  typedef struct KLineCcmTag {
    KLineCcmTx ccmTx;
    KLineCcmRx ccmRx;
  }  KLineCcm;

  // Initialize the PAKM side
  void KLineCcmInitPAKM(
    KLineCcm *pThis,
    const KLinePairing *pPairing);

  void KLineCcmInitCEM(
    KLineCcm *pThis,
    const KLinePairing *pPairing);

  void KLineCcmChallenge(
    KLineCcm * const pThis,
    const KLineChallenge txChallenge[15],
    const KLineChallenge rxChallenge[15]
  );

  typedef void (*RandombytesFnPtr)(void *p, uint8_t *pBuf, size_t bufLen);

  // Allocate an encrypted message.
  KLineMessage *KLineAllocEncryptMessage(
    KLineCcm *pThis,
    const uint8_t addr,
    const uint8_t func,
    const void *pPayloadSigned, // Signed data
    const size_t payloadSizeSigned, // Size of signed data
    const void *pPayloadEncrypted, // Encrypted data
    const size_t payloadSizeEncrypted // Size of encrypted data.
  );

  // Frees and decrypts pEncryptedMsg.
  // Returns non-null message if decryption is successfull.
  KLineMessage *KLineAllocDecryptMessage(
    KLineCcm *pThis,
    const KLineMessage * const pEncryptedMsg,
    const uint8_t **ppSigned,
    size_t *pSignedLen,
    const uint8_t **ppPlainText,
    size_t *pPlainTextLen
    );

  KLineMessage *KLineCreateChallenge(
    KLineCcm *pThis,
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData
  );

  KLineMessage *KLineCreatePairing(
    KLineCcm *pThis,
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData
  );

#ifdef __cplusplus
}
#endif


#endif