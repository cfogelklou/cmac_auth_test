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
#include "utils/packed.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#pragma warning(disable:4103)
#endif
#include "utils/pack_push.h"

  // Pairing of CEM to PAK
  typedef struct PACKED KLinePairingTag {
    uint8_t cemToPak[16];
    uint8_t pakToCem[16];
  } KLinePairing;

  // Challenge is 120 bits long
  typedef struct PACKED KLineChallengeTag{
    uint8_t challenge120[15]; // 120 bits
  } KLineChallenge;

  // Each message has a destination addr, a length, and specifies a function
  typedef struct PACKED KLineMessageHdrTag {
    uint8_t addr;
    uint8_t length;
    uint8_t function;    
  } KLineMessageHdr;
  
  // Every physical message has a checksum, which is an XOR of all bits in the packet.
  typedef struct PACKED KLineMessageFtrTag {
    uint8_t cs;
  } KLineMessageFtr;

  // Authenticaded messages are packed inside a KLineMessage 
  // (see the union in KLineMessage)
  typedef struct PACKED KLineAuthMessageHdrTag {
    // txcnt is another 8-bits of the 128-bit nonce used for message authentication. Shall never roll over.
    uint8_t txcnt; 
    // Specifies the length H, in bytes, of unencrypted, signed data preceding encrypted data. Also referred to as SPAYLOAD length.
    uint8_t sdata_len; 
  } KLineAuthMessageHdr;

  // The last 8 bits of an authenticated message is the signature.
  typedef struct PACKED KLineAuthMessageFtrTag {
    uint8_t sig[8];
  } KLineAuthMessageFtr;

  // An authenticaed message consists of the header, then signed, then encrypted data, then footer.
  typedef struct PACKED KLineAuthMessageTag {
    KLineAuthMessageHdr hdr;
    uint8_t sdata_and_edata[1];
#ifdef KLINE_CCM
    uint8_t edata[1];
#endif
    KLineAuthMessageFtr ftr;
  } KLineAuthMessage;

  // KLine message. Note, this shall never be used directly - it is simply for reference.
  // Messages must be allocated dynamically depending on the size of the payload.  
  // Location of "ftr" will therefore vary 
  // depending on the size of the payload.
  typedef struct PACKED KLineMessageTag {
    KLineMessageHdr hdr;
    union {
      KLinePairing    pairing;
      KLineChallenge  challenge;
      KLineAuthMessage aead;
      uint8_t          payload[1];
    }u;
    
    // Footer contains checksum. Note its placement must be calculated depending on length of the message.
    KLineMessageFtr ftr;
  } KLineMessage;

#include "utils/pack_pop.h"
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
    union {
      struct {
        uint8_t tx_cnt;
        KLineChallenge challenge;
      } noncePlusChallenge;
      struct {
        uint8_t iv[16];
      }iv;
    } nonce;
  } KLineAuthTxRx;

  // Object which handles transmission and reception of authenticated messages.
  typedef struct KLineAuthTag {
    KLineAuthTxRx authTx;
    KLineAuthTxRx authRx;
  }  KLineAuth;

  // Initialize the PAKM side
  void KLineAuthPairPAKM(
    KLineAuth * const pThis,
    const KLinePairing *pPairing);

  // Initialize the CEM side from a KLinePairing struct.
  void KLineAuthPairCEM(
    KLineAuth * const pThis,
    const KLinePairing *pPairing);

  void KLineAuthDestruct(
    KLineAuth * const pThis
  );

  void KLineAuthChallenge(
    KLineAuth * const pThis,
    /// txChallenge: Sets the 120-bit challenge set by the remote device, 
    // allowing ourselves to authenticate
    const KLineChallenge *txChallenge,

    /// rxChallenge: Sets the challenge set locally, allowing the remote to authenticate.
    const KLineChallenge *rxChallenge
  );

  // Optional callback to allow generation of random data.
  typedef void (*RandombytesFnPtr)(void *p, uint8_t *pBuf, size_t bufLen);

  // Create a challenge message.
  KLineMessage *KLineCreateChallenge(
    KLineAuth * const pThis,
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData
  );

  // Create a pairing message.
  KLineMessage *KLineCreatePairing(
    KLineAuth * const pThis,
    const uint8_t addr,
    const uint8_t func,
    RandombytesFnPtr randFn,
    void *randFnData
  );

  // Allocate an encrypted message.
  KLineMessage *KLineAllocAuthenticatedMessage(
    KLineAuth * const pThis,
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
    KLineAuth * const pThis,
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