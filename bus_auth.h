#ifndef BUS_AUTHENTICATION_H__
#define BUS_AUTHENTICATION_H__

#include "cmac.h"


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

#define SK_BYTES 16
#define CHALLENGE_BITS 120
#define SIGNATURE_BYTES 8
#define MAX_MISSED_MESSAGES 10

// Pairing of CEM to PAK
typedef struct PACKED KLinePairingTag {
  // New SK (128 bits) (AES-CMAC-128 for CEM->PAK)
  uint8_t cemToPak[SK_BYTES];
  // New SID(128 bits) (AES - CMAC - 128 for PAK->CEM)
  uint8_t pakToCem[SK_BYTES];
} KLinePairing;

// Challenge is 120 bits long
typedef struct PACKED KLineChallengeTag {
  uint8_t challenge120[CHALLENGE_BITS/8]; // 120 bits
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
  uint8_t sig[SIGNATURE_BYTES];
} KLineAuthMessageFtr;

// An authenticaed message consists of the header, then signed, then encrypted data, then footer.
typedef struct PACKED KLineAuthMessageTag {
  KLineAuthMessageHdr hdr;
  struct {
    union {
      struct {
        uint8_t scmd;
        uint8_t spayload[1];
      } sdata;
      uint8_t rawBytes[1];
    }u;
  } sdata;
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
    KLineAuthMessage auth;
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
int KLineCheckCs(const KLineMessage * const pM);

// Adds the CS to a message.
uint8_t KLineAddCs(KLineMessage * const pM);

// "Class" which can be used for receiving OR sending
// authenticated data.
typedef struct KLineAuthTxRxTag {
  mbedtls_cipher_context_t cmac;
  union {

    // Abstraction showing rx count first, 
    // followed by 120-bit challenge
    struct {
      uint8_t rx_cnt;
      KLineChallenge challenge;
    } rxNoncePlusChallenge;

    // Abstraction showing tx count first, 
    // followed by 120-bit challenge
    struct {
      uint8_t tx_cnt;
      KLineChallenge challenge;
    } txNoncePlusChallenge;

    // Abstraction mapping tx_cnt || challenge.
    struct {
      uint8_t byteArray[16];
    } entireNonce;

  } nonce;
} KLineAuthTxRx;

// "Class" which can be used for receiving AND sending
// authenticated data.
typedef struct KLineAuthTag {
  // Transmitter
  KLineAuthTxRx authTx;
  // Receiver
  KLineAuthTxRx authRx;
}  KLineAuth;

// Initializes with random data.
void KLineAuthInit(
  KLineAuth * const pThis
);

// Initialize the PAKM side
void KLineAuthPairPAKM(
  KLineAuth * const pThis,
  const KLinePairing *pPairing);

// Initialize the CEM side from a KLinePairing struct.
void KLineAuthPairCEM(
  KLineAuth * const pThis,
  const KLinePairing *pPairing);

// Gets the current TXCNT (next message)
uint8_t KLineAuthGetTxCnt(
  KLineAuth * const pThis
);

// Gets the current RXCNT (last received message.)
uint8_t KLineAuthGetRxCnt(
  KLineAuth * const pThis
);

void KLineAuthSetTxCnt(
  KLineAuth * const pThis,
  const uint8_t txcnt
);

// Destructor
void KLineAuthDestruct(
  KLineAuth * const pThis
);

// Optional callback to allow generation of random data.
typedef void(*RandombytesFnPtr)(void *p, uint8_t *pBuf, size_t bufLen);

// Create a challenge message.
KLineMessage *KLineCreateChallenge(
  const uint8_t addr,
  const uint8_t func,
  RandombytesFnPtr randFn,
  void *randFnData,
  // Set to >= 32 and < 120 to set number of challenge bits to < 120
  const size_t challengeLenBits
);

// Receives a 120-bit challenge
// The positive response is a signed “empty” message of type SCMD=0x80.  
// If the signature matches the expected signature calculated by the 
// message receiver, then the message receiver knows that the message 
// sender has the correct transmit key and challenge.
void KLineReceiveAuthChallenge(
  KLineAuth * const pThis,

  /// txChallenge: Sets the 120-bit challenge set by the remote device, 
  // allowing ourselves to authenticate
  const KLineChallenge *txChallenge,

  /// rxChallenge: Sets the challenge set locally, allowing the remote to authenticate.
  const KLineChallenge *rxChallenge,

  // Set to >= 32 and < 120 to set number of challenge bits to < 120
  const size_t challengeLenBits,

  // Set to non-null to allocate a response
  KLineMessage **ppTxChallengeResponse
);

// Create a pairing message.
KLineMessage *KLineCreatePairing(
  const uint8_t addr,
  const uint8_t func,
  RandombytesFnPtr randFn,
  void *randFnData
);

// Allocate an encrypted message.
KLineMessage *KLineCreateAuthenticatedMessage(
  KLineAuth * const pThis,
  const uint8_t addr,
  const uint8_t func,
  // Signed command.
  const uint8_t scmd,
  // Signed payload buffer.
  const void *pSPayload,
  // Size of signed payload buffer.
  const size_t szSPayload
);

// Returns true if authenticated.
bool KLineAuthenticateMessage(
  KLineAuth * const pThis,
  /// Incoming message.
  const KLineMessage * const pMsg,
  /// Outputs the signed part of the incoming data    
  const KLineAuthMessage **ppSigned
);

void KLineTestCmac(
  const uint8_t key[SK_BYTES],
  const uint8_t *buf,
  const size_t buflen,
  uint8_t signature[16]
);

#ifdef __cplusplus
}
#endif


#endif
