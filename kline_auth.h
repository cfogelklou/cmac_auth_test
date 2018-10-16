#ifndef KLINE_CCM_H__
#define KLINE_CCM_H__

#ifndef KLINE_CMAC
#include "ccm.h"
#define KLINE_CCM
#else
#include "cmac.h"
#endif

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

  typedef struct PACKED KLineAuthMessageHdrTag {
    uint8_t txcnt; // Least Significant Bits of 8-bit TXCNT part of message nonce.
    uint8_t sdata_len; // Specifies the length H, in bytes, of unencrypted, signed data preceding encrypted data. Also referred to as SPAYLOAD length.
  } KLineAuthMessageHdr;

  typedef struct PACKED KLineAuthMessageFtrTag {
    uint8_t sig[8];
  } KLineAuthMessageFtr;

  typedef struct PACKED KLineAuthMessageTag {
    KLineAuthMessageHdr hdr;
    uint8_t sdata_and_edata[1];
#ifdef KLINE_CCM
    uint8_t edata[1];
#endif
    KLineAuthMessageFtr ftr;
  } KLineAuthMessage;

  // Never use this object directly.
  typedef struct PACKED KLineMessageTag {
    KLineMessageHdr hdr;
    union {
      KLinePairing    pairing;
      KLineChallenge  challenge;
      KLineAuthMessage aead;
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

  typedef struct KLineAuthTxRxTag {
#ifdef KLINE_CCM
    mbedtls_ccm_context ccm;
#else
    mbedtls_cipher_context_t cmac;
#endif
    uint8_t noncePlusCnt[16];
  } KLineAuthTxRx;

  typedef struct KLineAuthTag {
    KLineAuthTxRx authTx;
    KLineAuthTxRx authRx;
  }  KLineAuth;

  // Initialize the PAKM side
  void KLineAuthPairPAKM(
    KLineAuth *pThis,
    const KLinePairing *pPairing);

  // Initialize the CEM side from a KLinePairing struct.
  void KLineAuthPairCEM(
    KLineAuth *pThis,
    const KLinePairing *pPairing);

  void KLineAuthDestruct(
    KLineAuth *pThis
  );

  void KLineAuthChallenge(
    KLineAuth * const pThis,
    /// txChallenge: Sets the 120-bit challenge set by the remote device, 
    // allowing ourselves to authenticate
    const KLineChallenge txChallenge[15],

    /// rxChallenge: Sets the challenge set locally, allowing the remote to authenticate.
    const KLineChallenge rxChallenge[15]
  );

  // Optional callback to allow generation of random data.
  typedef void (*RandombytesFnPtr)(void *p, uint8_t *pBuf, size_t bufLen);

  // Create a challenge message.
  KLineMessage *KLineCreateChallenge(
    KLineAuth *pThis,
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData
  );

  // Create a pairing message.
  KLineMessage *KLineCreatePairing(
    KLineAuth *pThis,
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData
  );

  // Allocate an encrypted message.
  KLineMessage *KLineAllocAuthenticatedMessage(
    KLineAuth *pThis,
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
    KLineAuth *pThis,
    const KLineMessage * const pEncryptedMsg,
    const uint8_t **ppSigned, ///< outputs the signed part of the incoming data
    size_t *pSignedLen, ///< outputs the length of the data in ppSigned
    const uint8_t **ppPlainText, ///< outputs the decrypted part of the incoming data.
    size_t *pPlainTextLen ///< outputs the length of the plaintext
  );

#ifdef __cplusplus
}
#endif


#endif