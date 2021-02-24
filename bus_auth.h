#ifndef BUS_AUTHENTICATION_H__
#define BUS_AUTHENTICATION_H__

#include "cmac.h"

#include <stdint.h>
#include <stdbool.h>
#include "utils/packed.h"
#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#pragma warning(disable : 4103)
#endif
#include "utils/pack_push.h"

#define SK_BYTES 16
#define CHALLENGE_BITS 120
#define SIGNATURE_BYTES 8
#define MAX_MISSED_MESSAGES 10

  // Pairing of CEM to PAK
  typedef struct PACKED BusLinePairingTag
  {
    // New SK (128 bits) (AES-CMAC-128 for CEM->PAK)
    uint8_t cemToPak[SK_BYTES];
    // New SID(128 bits) (AES - CMAC - 128 for PAK->CEM)
    uint8_t pakToCem[SK_BYTES];
  } BusLinePairing;

  // Challenge is 120 bits long
  typedef struct PACKED BusLineChallengeTag
  {
    uint8_t challenge120[CHALLENGE_BITS / 8]; // 120 bits
  } BusLineChallenge;

  // Each message has a destination addr, a length, and specifies a function
  typedef struct PACKED BusLineMessageHdrTag
  {
    uint8_t addr;
    uint8_t length;
    uint8_t function;
  } BusLineMessageHdr;

  // Every physical message has a checksum, which is an XOR of all bits in the packet.
  typedef struct PACKED BusLineMessageFtrTag
  {
    uint8_t cs;
  } BusLineMessageFtr;

  // Authenticaded messages are packed inside a BusLineMessage
  // (see the union in BusLineMessage)
  typedef struct PACKED BusLineAuthMessageHdrTag
  {
    // txcnt is another 8-bits of the 128-bit nonce used for message authentication. Shall never roll over.
    uint8_t txcnt;
    // Specifies the length H, in bytes, of unencrypted, signed data preceding encrypted data. Also referred to as SPAYLOAD length.
    uint8_t sdata_len;
  } BusLineAuthMessageHdr;

  // The last 8 bits of an authenticated message is the signature.
  typedef struct PACKED BusLineAuthMessageFtrTag
  {
    uint8_t sig[SIGNATURE_BYTES];
  } BusLineAuthMessageFtr;

  // An authenticaed message consists of the header, then signed, then encrypted data, then footer.
  typedef struct PACKED BusLineAuthMessageTag
  {
    BusLineAuthMessageHdr hdr;
    struct
    {
      union
      {
        struct
        {
          uint8_t scmd;
          uint8_t spayload[1];
        } sdata;
        uint8_t rawBytes[1];
      } u;
    } sdata;
    BusLineAuthMessageFtr ftr;
  } BusLineAuthMessage;

  // BusLine message. Note, this shall never be used directly - it is simply for reference.
  // Messages must be allocated dynamically depending on the size of the payload.
  // Location of "ftr" will therefore vary
  // depending on the size of the payload.
  typedef struct PACKED BusLineMessageTag
  {
    BusLineMessageHdr hdr;
    union
    {
      BusLinePairing pairing;
      BusLineChallenge challenge;
      BusLineAuthMessage auth;
      uint8_t payload[1];
    } u;

    // Footer contains checksum. Note its placement must be calculated depending on length of the message.
    BusLineMessageFtr ftr;
  } BusLineMessage;

#include "utils/pack_pop.h"
#ifdef WIN32
#pragma warning(default : 4103)
#endif

  // Allocates a non-encrypted message
  BusLineMessage *BusLineAllocMessage(
      const uint8_t addr,
      const uint8_t func,
      const size_t payloadSize,
      void *pPayloadCanBeNull);

  // Frees a non-encrypted challenge
  void BusLineFreeMessage(BusLineMessage *pM);

  // Checks the CS on a message
  int BusLineCheckCs(const BusLineMessage *const pM);

  // Adds the CS to a message.
  uint8_t BusLineAddCs(BusLineMessage *const pM);

  // "Class" which can be used for receiving OR sending
  // authenticated data.
  typedef struct BusLineAuthTxRxTag
  {
    mbedtls_cipher_context_t cmac;
    union
    {

      // Abstraction showing rx count first,
      // followed by 120-bit challenge
      struct
      {
        uint8_t rx_cnt;
        BusLineChallenge challenge;
      } rxNoncePlusChallenge;

      // Abstraction showing tx count first,
      // followed by 120-bit challenge
      struct
      {
        uint8_t tx_cnt;
        BusLineChallenge challenge;
      } txNoncePlusChallenge;

      // Abstraction mapping tx_cnt || challenge.
      struct
      {
        uint8_t byteArray[16];
      } entireNonce;

    } nonce;
  } BusLineAuthTxRx;

  // "Class" which can be used for receiving AND sending
  // authenticated data.
  typedef struct BusLineAuthTag
  {
    // Transmitter
    BusLineAuthTxRx authTx;
    // Receiver
    BusLineAuthTxRx authRx;
  } BusLineAuth;

  // Initializes with random data.
  void BusLineAuthInit(
      BusLineAuth *const pThis);

  // Initialize the PAKM side
  void BusLineAuthPairPAKM(
      BusLineAuth *const pThis,
      const BusLinePairing *pPairing);

  // Initialize the CEM side from a BusLinePairing struct.
  void BusLineAuthPairCEM(
      BusLineAuth *const pThis,
      const BusLinePairing *pPairing);

  // Gets the current TXCNT (next message)
  uint8_t BusLineAuthGetTxCnt(
      BusLineAuth *const pThis);

  // Gets the current RXCNT (last received message.)
  uint8_t BusLineAuthGetRxCnt(
      BusLineAuth *const pThis);

  void BusLineAuthSetTxCnt(
      BusLineAuth *const pThis,
      const uint8_t txcnt);

  // Destructor
  void BusLineAuthDestruct(
      BusLineAuth *const pThis);

  // Optional callback to allow generation of random data.
  typedef void (*RandombytesFnPtr)(void *p, uint8_t *pBuf, size_t bufLen);

  // Create a challenge message.
  BusLineMessage *BusLineCreateChallenge(
      const uint8_t addr,
      const uint8_t func,
      RandombytesFnPtr randFn,
      void *randFnData,
      // Set to >= 32 and < 120 to set number of challenge bits to < 120
      const size_t challengeLenBits);

  // Receives a 120-bit challenge
  // The positive response is a signed �empty� message of type SCMD=0x80.
  // If the signature matches the expected signature calculated by the
  // message receiver, then the message receiver knows that the message
  // sender has the correct transmit key and challenge.
  void BusLineReceiveAuthChallenge(
      BusLineAuth *const pThis,

      /// txChallenge: Sets the 120-bit challenge set by the remote device,
      // allowing ourselves to authenticate
      const BusLineChallenge *txChallenge,

      /// rxChallenge: Sets the challenge set locally, allowing the remote to authenticate.
      const BusLineChallenge *rxChallenge,

      // Set to >= 32 and < 120 to set number of challenge bits to < 120
      const size_t challengeLenBits,

      // Set to non-null to allocate a response
      BusLineMessage **ppTxChallengeResponse);

  // Create a pairing message.
  BusLineMessage *BusLineCreatePairing(
      const uint8_t addr,
      const uint8_t func,
      RandombytesFnPtr randFn,
      void *randFnData);

  // Allocate an encrypted message.
  BusLineMessage *BusLineCreateAuthenticatedMessage(
      BusLineAuth *const pThis,
      const uint8_t addr,
      const uint8_t func,
      // Signed command.
      const uint8_t scmd,
      // Signed payload buffer.
      const void *pSPayload,
      // Size of signed payload buffer.
      const size_t szSPayload);

  // Returns true if authenticated.
  bool BusLineAuthenticateMessage(
      BusLineAuth *const pThis,
      /// Incoming message.
      const BusLineMessage *const pMsg,
      /// Outputs the signed part of the incoming data
      const BusLineAuthMessage **ppSigned);

  void BusLineTestCmac(
      const uint8_t key[SK_BYTES],
      const uint8_t *buf,
      const size_t buflen,
      uint8_t signature[16]);

  void BusLineTestCmacCifra(
      const uint8_t key[SK_BYTES],
      const uint8_t *buf,
      const size_t buflen,
      uint8_t signature[16]);

#ifdef __cplusplus
}
#endif

#endif
