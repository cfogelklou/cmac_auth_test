#ifndef KLINE_CCM_H__
#define KLINE_CCM_H__

#include <stdint.h>
#include "packed.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#pragma warning(disable:4103)
#endif
#include "pack_push.h"


  typedef struct PACKED KLinePairingTag {
    uint8_t sk[16];
    uint8_t sid[16];
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

  // Never use this object directly.
  typedef struct PACKED KLineMessageTag {
    KLineMessageHdr hdr;
    union {
      KLinePairing    pairing;
      KLineChallenge  challenge;
      uint8_t          payload[1];
    }u;
    KLineMessageFtr ftr;
  } KLineMessage;

#include "pack_pop.h"
#ifdef WIN32
#pragma warning(default:4103)
#endif

  KLineMessage *KLineAllocMessage(
    const uint8_t addr,
    const uint8_t func,
    const size_t payloadSize, 
    void *pPayloadCanBeNull);

  void KLineFreeMessage(KLineMessage *pM);

  int KLineCheckCs(KLineMessage * const pM);

  uint8_t KLineAddCs(KLineMessage * const pM);

#ifdef __cplusplus
}
#endif


#endif