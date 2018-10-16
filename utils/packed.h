#ifndef PACKED
#if defined (__IAR_SYSTEMS_ICC__)
#define XDATA
#define CODE
#define DATA_ALIGN(x)               _Pragma data_alignment=(x)
#define PACKED                      __packed
#define PACKED_STRUCT               PACKED struct
#define PACKED_TYPEDEF_STRUCT       PACKED typedef struct
#define PACKED_TYPEDEF_CONST_STRUCT PACKED typedef const struct
#define PACKED_TYPEDEF_UNION        PACKED typedef union

#elif defined __TI_COMPILER_VERSION || defined __TI_COMPILER_VERSION__
#define XDATA
#define CODE
#define DATA
#define NEARFUNC
#define PACKED                      __attribute__((__packed__))
#define PACKED_STRUCT               struct PACKED
#define PACKED_TYPEDEF_STRUCT       typedef struct PACKED
#define PACKED_TYPEDEF_CONST_STRUCT typedef const struct PACKED
#define PACKED_TYPEDEF_UNION        typedef union PACKED

#elif defined (__GNUC__)
#ifndef PACKED
#  define PACKED __attribute__((__packed__))
#endif
#define PACKED_STRUCT               struct PACKED
#define PACKED_TYPEDEF_STRUCT       typedef struct PACKED
#define PACKED_TYPEDEF_CONST_STRUCT typedef const struct PACKED
#define PACKED_TYPEDEF_UNION        typedef union PACKED

#else
#define PACKED
#endif
#endif // PACKED

