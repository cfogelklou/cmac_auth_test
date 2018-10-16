#ifdef WIN32
// push current alignment rules to internal stack
#pragma pack(push)
// force 1-byte alignment boundary
#pragma pack(1)
// define PACKED to nothing if not already defined
#ifndef PACKED
#define PACKED
#endif // PACKED

#else // WIN32

// define PACKED to something gcc understands, if not already defined
#ifndef PACKED
#define PACKED __attribute__((packed))
#endif // PACKED
#endif // WIN32
