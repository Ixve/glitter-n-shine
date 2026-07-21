








#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable:4091) 
#endif

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#include <windows.h>
#include <limits.h>


#define DETOURS_INTERNAL

#include "detours.h"

#if DETOURS_VERSION != 0x4c0c1   
#error detours.h version mismatch
#endif

#if _MSC_VER >= 1900
#pragma warning(pop)
#endif

#undef ASSERT
#define ASSERT(x)








#if defined(DETOURS_X86_OFFLINE_LIBRARY) \
 || defined(DETOURS_X64_OFFLINE_LIBRARY) \
 || defined(DETOURS_ARM_OFFLINE_LIBRARY) \
 || defined(DETOURS_ARM64_OFFLINE_LIBRARY) \
 || defined(DETOURS_IA64_OFFLINE_LIBRARY)

#undef DETOURS_X64
#undef DETOURS_X86
#undef DETOURS_IA64
#undef DETOURS_ARM
#undef DETOURS_ARM64

#if defined(DETOURS_X86_OFFLINE_LIBRARY)

#define DetourCopyInstruction   DetourCopyInstructionX86
#define DetourSetCodeModule     DetourSetCodeModuleX86
#define CDetourDis              CDetourDisX86
#define DETOURS_X86

#elif defined(DETOURS_X64_OFFLINE_LIBRARY)

#if !defined(DETOURS_64BIT)


#endif

#define DetourCopyInstruction   DetourCopyInstructionX64
#define DetourSetCodeModule     DetourSetCodeModuleX64
#define CDetourDis              CDetourDisX64
#define DETOURS_X64

#elif defined(DETOURS_ARM_OFFLINE_LIBRARY)

#define DetourCopyInstruction   DetourCopyInstructionARM
#define DetourSetCodeModule     DetourSetCodeModuleARM
#define CDetourDis              CDetourDisARM
#define DETOURS_ARM

#elif defined(DETOURS_ARM64_OFFLINE_LIBRARY)

#define DetourCopyInstruction   DetourCopyInstructionARM64
#define DetourSetCodeModule     DetourSetCodeModuleARM64
#define CDetourDis              CDetourDisARM64
#define DETOURS_ARM64

#elif defined(DETOURS_IA64_OFFLINE_LIBRARY)

#define DetourCopyInstruction   DetourCopyInstructionIA64
#define DetourSetCodeModule     DetourSetCodeModuleIA64
#define DETOURS_IA64

#else

#error

#endif
#endif





























































#pragma data_seg(".detourd")
#pragma const_seg(".detourc")





#if defined(DETOURS_X64) || defined(DETOURS_X86)

class CDetourDis
{
  public:
    CDetourDis(_Out_opt_ PBYTE *ppbTarget,
               _Out_opt_ LONG *plExtra);

    PBYTE   CopyInstruction(PBYTE pbDst, PBYTE pbSrc);
    static BOOL SanityCheckSystem();
    static BOOL SetCodeModule(PBYTE pbBeg, PBYTE pbEnd, BOOL fLimitReferencesToModule);

  public:
    struct COPYENTRY;
    typedef const COPYENTRY * REFCOPYENTRY;

    typedef PBYTE (CDetourDis::* COPYFUNC)(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    
    enum {
        DYNAMIC     = 0x1u,
        ADDRESS     = 0x2u,
        NOENLARGE   = 0x4u,
        RAX         = 0x8u,
    };

    
    enum {
        SIB         = 0x10u,
        RIP         = 0x20u,
        NOTSIB      = 0x0fu,
    };

    struct COPYENTRY
    {
        
        ULONG       nOpcode         : 8;    
        ULONG       nFixedSize      : 4;    
        ULONG       nFixedSize16    : 4;    
        ULONG       nModOffset      : 4;    
        ULONG       nRelOffset      : 4;    
        ULONG       nTargetBack     : 4;    
        ULONG       nFlagBits       : 4;    
        COPYFUNC    pfCopy;                 
    };

  protected:
    
#define ENTRY_DataIgnored           0, 0, 0, 0, 0, 0,
#define ENTRY_CopyBytes1            1, 1, 0, 0, 0, 0, &CDetourDis::CopyBytes
#ifdef DETOURS_X64
#define ENTRY_CopyBytes1Address     9, 5, 0, 0, 0, ADDRESS, &CDetourDis::CopyBytes
#else
#define ENTRY_CopyBytes1Address     5, 3, 0, 0, 0, ADDRESS, &CDetourDis::CopyBytes
#endif
#define ENTRY_CopyBytes1Dynamic     1, 1, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2            2, 2, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Jump        ENTRY_DataIgnored &CDetourDis::CopyBytesJump
#define ENTRY_CopyBytes2CantJump    2, 2, 0, 1, 0, NOENLARGE, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Dynamic     2, 2, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3            3, 3, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Dynamic     3, 3, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5         5, 3, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5Dynamic  5, 3, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes 
#ifdef DETOURS_X64
#define ENTRY_CopyBytes3Or5Rax      5, 3, 0, 0, 0, RAX, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5Target   5, 5, 0, 1, 0, 0, &CDetourDis::CopyBytes
#else
#define ENTRY_CopyBytes3Or5Rax      5, 3, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5Target   5, 3, 0, 1, 0, 0, &CDetourDis::CopyBytes
#endif
#define ENTRY_CopyBytes4            4, 4, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes5            5, 5, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes5Or7Dynamic  7, 5, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes7            7, 7, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Mod         2, 2, 1, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2ModDynamic  2, 2, 1, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Mod1        3, 3, 1, 0, 1, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2ModOperand  6, 4, 1, 0, 4, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Mod         3, 3, 2, 0, 0, 0, &CDetourDis::CopyBytes 
#define ENTRY_CopyBytes3Mod1        4, 4, 2, 0, 1, 0, &CDetourDis::CopyBytes 
#define ENTRY_CopyBytesPrefix       ENTRY_DataIgnored &CDetourDis::CopyBytesPrefix
#define ENTRY_CopyBytesSegment      ENTRY_DataIgnored &CDetourDis::CopyBytesSegment
#define ENTRY_CopyBytesRax          ENTRY_DataIgnored &CDetourDis::CopyBytesRax
#define ENTRY_CopyF2                ENTRY_DataIgnored &CDetourDis::CopyF2
#define ENTRY_CopyF3                ENTRY_DataIgnored &CDetourDis::CopyF3   
#define ENTRY_Copy0F                ENTRY_DataIgnored &CDetourDis::Copy0F
#define ENTRY_Copy0F78              ENTRY_DataIgnored &CDetourDis::Copy0F78
#define ENTRY_Copy0F00              ENTRY_DataIgnored &CDetourDis::Copy0F00 
#define ENTRY_Copy0FB8              ENTRY_DataIgnored &CDetourDis::Copy0FB8 
#define ENTRY_Copy66                ENTRY_DataIgnored &CDetourDis::Copy66
#define ENTRY_Copy67                ENTRY_DataIgnored &CDetourDis::Copy67
#define ENTRY_CopyF6                ENTRY_DataIgnored &CDetourDis::CopyF6
#define ENTRY_CopyF7                ENTRY_DataIgnored &CDetourDis::CopyF7
#define ENTRY_CopyFF                ENTRY_DataIgnored &CDetourDis::CopyFF
#define ENTRY_CopyVex2              ENTRY_DataIgnored &CDetourDis::CopyVex2
#define ENTRY_CopyVex3              ENTRY_DataIgnored &CDetourDis::CopyVex3
#define ENTRY_Invalid               ENTRY_DataIgnored &CDetourDis::Invalid
#define ENTRY_End                   ENTRY_DataIgnored NULL

    PBYTE CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesSegment(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesRax(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesJump(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    PBYTE Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    PBYTE AdjustTarget(PBYTE pbDst, PBYTE pbSrc, UINT cbOp,
                       UINT cbTargetOffset, UINT cbTargetSize);

  protected:
    PBYTE Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy0F00(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); 
    PBYTE Copy0F78(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); 
    PBYTE Copy0FB8(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); 
    PBYTE Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); 
    PBYTE CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyFF(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVex2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVex3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc);

  protected:
    static const COPYENTRY  s_rceCopyTable[257];
    static const COPYENTRY  s_rceCopyTable0F[257];
    static const BYTE       s_rbModRm[256];
    static PBYTE            s_pbModuleBeg;
    static PBYTE            s_pbModuleEnd;
    static BOOL             s_fLimitReferencesToModule;

  protected:
    BOOL                m_bOperandOverride;
    BOOL                m_bAddressOverride;
    BOOL                m_bRaxOverride; 
    BOOL                m_bVex;
    BOOL                m_bF2;
    BOOL                m_bF3; 
    BYTE                m_nSegmentOverride;

    PBYTE *             m_ppbTarget;
    LONG *              m_plExtra;

    LONG                m_lScratchExtra;
    PBYTE               m_pbScratchTarget;
    BYTE                m_rbScratchDst[64];
};

PVOID WINAPI DetourCopyInstruction(_In_opt_ PVOID pDst,
                                   _Inout_opt_ PVOID *ppDstPool,
                                   _In_ PVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget,
                                   _Out_opt_ LONG *plExtra)
{
    UNREFERENCED_PARAMETER(ppDstPool);  

    CDetourDis oDetourDisasm((PBYTE*)ppTarget, plExtra);
    return oDetourDisasm.CopyInstruction((PBYTE)pDst, (PBYTE)pSrc);
}



CDetourDis::CDetourDis(_Out_opt_ PBYTE *ppbTarget, _Out_opt_ LONG *plExtra)
{
    m_bOperandOverride = FALSE;
    m_bAddressOverride = FALSE;
    m_bRaxOverride = FALSE;
    m_bF2 = FALSE;
    m_bF3 = FALSE;
    m_bVex = FALSE;

    m_ppbTarget = ppbTarget ? ppbTarget : &m_pbScratchTarget;
    m_plExtra = plExtra ? plExtra : &m_lScratchExtra;

    *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_NONE;
    *m_plExtra = 0;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pbDst, PBYTE pbSrc)
{
    
    if (NULL == pbDst) {
        pbDst = m_rbScratchDst;
    }
    if (NULL == pbSrc) {
        
        SetLastError(ERROR_INVALID_DATA);
        return NULL;
    }

    
    
    
    REFCOPYENTRY pEntry = &s_rceCopyTable[pbSrc[0]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    UINT nBytesFixed;

    ASSERT(!m_bVex || pEntry->nFlagBits == 0);
    ASSERT(!m_bVex || pEntry->nFixedSize == pEntry->nFixedSize16);

    UINT const nModOffset = pEntry->nModOffset;
    UINT const nFlagBits = pEntry->nFlagBits;
    UINT const nFixedSize = pEntry->nFixedSize;
    UINT const nFixedSize16 = pEntry->nFixedSize16;

    if (nFlagBits & ADDRESS) {
        nBytesFixed = m_bAddressOverride ? nFixedSize16 : nFixedSize;
    }
#ifdef DETOURS_X64
    
    else if (m_bRaxOverride) {
        nBytesFixed = nFixedSize + ((nFlagBits & RAX) ? 4 : 0);
    }
#endif
    else {
        nBytesFixed = m_bOperandOverride ? nFixedSize16 : nFixedSize;
    }

    UINT nBytes = nBytesFixed;
    UINT nRelOffset = pEntry->nRelOffset;
    UINT cbTarget = nBytes - nRelOffset;
    if (nModOffset > 0) {
        ASSERT(nRelOffset == 0);
        BYTE const bModRm = pbSrc[nModOffset];
        BYTE const bFlags = s_rbModRm[bModRm];

        nBytes += bFlags & NOTSIB;

        if (bFlags & SIB) {
            BYTE const bSib = pbSrc[nModOffset + 1];

            if ((bSib & 0x07) == 0x05) {
                if ((bModRm & 0xc0) == 0x00) {
                    nBytes += 4;
                }
                else if ((bModRm & 0xc0) == 0x40) {
                    nBytes += 1;
                }
                else if ((bModRm & 0xc0) == 0x80) {
                    nBytes += 4;
                }
            }
            cbTarget = nBytes - nRelOffset;
        }
#ifdef DETOURS_X64
        else if (bFlags & RIP) {
            UINT nTargetBack = pEntry->nTargetBack;
            
            
            ASSERT(nTargetBack == 0 || nTargetBack == 1 || nTargetBack == 4);
            if (nTargetBack == 4 && m_bOperandOverride && !m_bRaxOverride) {
                nTargetBack = 2;
            }

            nRelOffset = nBytes - (4 + nTargetBack);
            cbTarget = 4;
        }
#endif
    }
    CopyMemory(pbDst, pbSrc, nBytes);

    if (nRelOffset) {
        *m_ppbTarget = AdjustTarget(pbDst, pbSrc, nBytes, nRelOffset, cbTarget);
#ifdef DETOURS_X64
        if (pEntry->nRelOffset == 0) {
            
            *m_ppbTarget = NULL;
        }
#endif
    }
    if (nFlagBits & NOENLARGE) {
        *m_plExtra = -*m_plExtra;
    }
    if (nFlagBits & DYNAMIC) {
        *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }
    return pbSrc + nBytes;
}

PBYTE CDetourDis::CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    pbDst[0] = pbSrc[0];
    pEntry = &s_rceCopyTable[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::CopyBytesSegment(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{
    m_nSegmentOverride = pbSrc[0];
    return CopyBytesPrefix(0, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytesRax(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{ 
    if (pbSrc[0] & 0x8) {
        m_bRaxOverride = TRUE;
    }
    return CopyBytesPrefix(0, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytesJump(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    PVOID pvSrcAddr = &pbSrc[1];
    PVOID pvDstAddr = NULL;
    LONG_PTR nOldOffset = (LONG_PTR)*(signed char*&)pvSrcAddr;
    LONG_PTR nNewOffset = 0;

    *m_ppbTarget = pbSrc + 2 + nOldOffset;

    if (pbSrc[0] == 0xeb) {
        pbDst[0] = 0xe9;
        pvDstAddr = &pbDst[1];
        nNewOffset = nOldOffset - ((pbDst - pbSrc) + 3);
        *(UNALIGNED LONG*&)pvDstAddr = (LONG)nNewOffset;

        *m_plExtra = 3;
        return pbSrc + 2;
    }

    ASSERT(pbSrc[0] >= 0x70 && pbSrc[0] <= 0x7f);

    pbDst[0] = 0x0f;
    pbDst[1] = 0x80 | (pbSrc[0] & 0xf);
    pvDstAddr = &pbDst[2];
    nNewOffset = nOldOffset - ((pbDst - pbSrc) + 4);
    *(UNALIGNED LONG*&)pvDstAddr = (LONG)nNewOffset;

    *m_plExtra = 4;
    return pbSrc + 2;
}

PBYTE CDetourDis::AdjustTarget(PBYTE pbDst, PBYTE pbSrc, UINT cbOp,
                               UINT cbTargetOffset, UINT cbTargetSize)
{
    PBYTE pbTarget = NULL;
#if 1 
#if defined(DETOURS_X64)
    typedef LONGLONG T;
#else
    typedef LONG T;
#endif
    T nOldOffset;
    T nNewOffset;
    PVOID pvTargetAddr = &pbDst[cbTargetOffset];

    switch (cbTargetSize) {
      case 1:
        nOldOffset = *(signed char*&)pvTargetAddr;
        break;
      case 2:
        nOldOffset = *(UNALIGNED SHORT*&)pvTargetAddr;
        break;
      case 4:
        nOldOffset = *(UNALIGNED LONG*&)pvTargetAddr;
        break;
#if defined(DETOURS_X64)
      case 8:
        nOldOffset = *(UNALIGNED LONGLONG*&)pvTargetAddr;
        break;
#endif
      default:
        ASSERT(!"cbTargetSize is invalid.");
        nOldOffset = 0;
        break;
    }

    pbTarget = pbSrc + cbOp + nOldOffset;
    nNewOffset = nOldOffset - (T)(pbDst - pbSrc);

    switch (cbTargetSize) {
      case 1:
        *(CHAR*&)pvTargetAddr = (CHAR)nNewOffset;
        if (nNewOffset < SCHAR_MIN || nNewOffset > SCHAR_MAX) {
            *m_plExtra = sizeof(ULONG) - 1;
        }
        break;
      case 2:
        *(UNALIGNED SHORT*&)pvTargetAddr = (SHORT)nNewOffset;
        if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX) {
            *m_plExtra = sizeof(ULONG) - 2;
        }
        break;
      case 4:
        *(UNALIGNED LONG*&)pvTargetAddr = (LONG)nNewOffset;
        if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX) {
            *m_plExtra = sizeof(ULONG) - 4;
        }
        break;
#if defined(DETOURS_X64)
      case 8:
        *(UNALIGNED LONGLONG*&)pvTargetAddr = nNewOffset;
        break;
#endif
    }
#ifdef DETOURS_X64
    
    
    

    if (pbDst >= m_rbScratchDst && pbDst < (sizeof(m_rbScratchDst) + m_rbScratchDst)) {
        ASSERT((((size_t)pbDst + cbOp + nNewOffset) & 0xFFFFFFFF) == (((size_t)pbTarget) & 0xFFFFFFFF));
    }
    else
#endif
    {
        ASSERT(pbDst + cbOp + nNewOffset == pbTarget);
    }
#endif
    return pbTarget;
}

PBYTE CDetourDis::Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pbDst;
    (void)pEntry;
    ASSERT(!"Invalid Instruction");
    return pbSrc + 1;
}



PBYTE CDetourDis::Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    pbDst[0] = pbSrc[0];
    pEntry = &s_rceCopyTable0F[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::Copy0F78(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{
    

    static const COPYENTRY vmread = { 0x78, ENTRY_CopyBytes2Mod };
    static const COPYENTRY extrq_insertq = { 0x78, ENTRY_CopyBytes4 };

    ASSERT(!(m_bF2 && m_bOperandOverride));

    
    
    

    REFCOPYENTRY const pEntry = ((m_bF2 || m_bOperandOverride) ? &extrq_insertq : &vmread);

    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy0F00(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{
    
    

    static const COPYENTRY other = { 0xB8, ENTRY_CopyBytes2Mod }; 
    static const COPYENTRY jmpe = { 0xB8, ENTRY_CopyBytes2ModDynamic }; 

    REFCOPYENTRY const pEntry = (((6 << 3) == ((7 << 3) & pbSrc[1])) ?  &jmpe : &other);
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy0FB8(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{
    

    static const COPYENTRY popcnt = { 0xB8, ENTRY_CopyBytes2Mod };
    static const COPYENTRY jmpe = { 0xB8, ENTRY_CopyBytes3Or5Dynamic }; 
    REFCOPYENTRY const pEntry = m_bF3 ? &popcnt : &jmpe;
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   
    m_bOperandOverride = TRUE;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   
    m_bAddressOverride = TRUE;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    m_bF2 = TRUE;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{ 
    m_bF3 = TRUE;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    
    if (0x00 == (0x38 & pbSrc[1])) {    
        static const COPYENTRY ce = { 0xf6, ENTRY_CopyBytes2Mod1 };
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }
    
    
    
    
    
    

    static const COPYENTRY ce = { 0xf6, ENTRY_CopyBytes2Mod };
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    
    if (0x00 == (0x38 & pbSrc[1])) {    
        static const COPYENTRY ce = { 0xf7, ENTRY_CopyBytes2ModOperand };
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }

    
    
    
    
    
    
    static const COPYENTRY ce = { 0xf7, ENTRY_CopyBytes2Mod };
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyFF(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   
    
    
    
    
    
    
    
    (void)pEntry;

    static const COPYENTRY ce = { 0xff, ENTRY_CopyBytes2Mod };
    PBYTE pbOut = (this->*ce.pfCopy)(&ce, pbDst, pbSrc);

    BYTE const b1 = pbSrc[1];

    if (0x15 == b1 || 0x25 == b1) {         
#ifdef DETOURS_X64
        
        if (m_nSegmentOverride != 0x64 && m_nSegmentOverride != 0x65)
#else
        if (m_nSegmentOverride == 0 || m_nSegmentOverride == 0x2E)
#endif
        {
#ifdef DETOURS_X64
            INT32 offset = *(UNALIGNED INT32*)&pbSrc[2];
            PBYTE *ppbTarget = (PBYTE *)(pbSrc + 6 + offset);
#else
            PBYTE *ppbTarget = (PBYTE *)(SIZE_T)*(UNALIGNED ULONG*)&pbSrc[2];
#endif
            if (s_fLimitReferencesToModule &&
                (ppbTarget < (PVOID)s_pbModuleBeg || ppbTarget >= (PVOID)s_pbModuleEnd)) {

                *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
            }
            else {
                
                *m_ppbTarget = *ppbTarget;
            }
        }
        else {
            *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
        }
    }
    else if (0x10 == (0x30 & b1) || 
             0x20 == (0x30 & b1)) { 
        *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }
    return pbOut;
}

PBYTE CDetourDis::CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc)


{
    static const COPYENTRY ceF38 = { 0x38, ENTRY_CopyBytes2Mod };
    static const COPYENTRY ceF3A = { 0x3A, ENTRY_CopyBytes2Mod1 };
    static const COPYENTRY Invalid = { 0xC4, ENTRY_Invalid };

    m_bVex = TRUE;
    REFCOPYENTRY pEntry;
    switch (m) {
    default: pEntry = &Invalid; break;
    case 1:  pEntry = &s_rceCopyTable0F[pbSrc[0]]; break;
    case 2:  pEntry = &ceF38; break;
    case 3:  pEntry = &ceF3A; break;
    }

    switch (pbSrc[-1] & 3) { 
    case 0: break;
    case 1: m_bOperandOverride = TRUE; break;
    case 2: m_bF3 = TRUE; break;
    case 3: m_bF2 = TRUE; break;
    }

    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyVex3(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)

{
#ifdef DETOURS_X86
    const static COPYENTRY ceLES = { 0xC4, ENTRY_CopyBytes2Mod };
    if ((pbSrc[1] & 0xC0) != 0xC0) {
        REFCOPYENTRY pEntry = &ceLES;
        return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
    }
#endif
    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];
    pbDst[2] = pbSrc[2];
#ifdef DETOURS_X64
    m_bRaxOverride |= !!(pbSrc[2] & 0x80); 
#else
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
#endif
    return CopyVexCommon(pbSrc[1] & 0x1F, pbDst + 3, pbSrc + 3);
}

PBYTE CDetourDis::CopyVex2(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)

{
#ifdef DETOURS_X86
    const static COPYENTRY ceLDS = { 0xC5, ENTRY_CopyBytes2Mod };
    if ((pbSrc[1] & 0xC0) != 0xC0) {
        REFCOPYENTRY pEntry = &ceLDS;
        return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
    }
#endif
    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];
    return CopyVexCommon(1, pbDst + 2, pbSrc + 2);
}



PBYTE CDetourDis::s_pbModuleBeg = NULL;
PBYTE CDetourDis::s_pbModuleEnd = (PBYTE)~(ULONG_PTR)0;
BOOL CDetourDis::s_fLimitReferencesToModule = FALSE;

BOOL CDetourDis::SetCodeModule(PBYTE pbBeg, PBYTE pbEnd, BOOL fLimitReferencesToModule)
{
    if (pbEnd < pbBeg) {
        return FALSE;
    }

    s_pbModuleBeg = pbBeg;
    s_pbModuleEnd = pbEnd;
    s_fLimitReferencesToModule = fLimitReferencesToModule;

    return TRUE;
}



const BYTE CDetourDis::s_rbModRm[256] = {
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, 
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, 
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, 
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, 
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                  
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable[257] =
{
    { 0x00, ENTRY_CopyBytes2Mod },                      
    { 0x01, ENTRY_CopyBytes2Mod },                      
    { 0x02, ENTRY_CopyBytes2Mod },                      
    { 0x03, ENTRY_CopyBytes2Mod },                      
    { 0x04, ENTRY_CopyBytes2 },                         
    { 0x05, ENTRY_CopyBytes3Or5 },                      
#ifdef DETOURS_X64
    { 0x06, ENTRY_Invalid },                            
    { 0x07, ENTRY_Invalid },                            
#else
    { 0x06, ENTRY_CopyBytes1 },                         
    { 0x07, ENTRY_CopyBytes1 },                         
#endif
    { 0x08, ENTRY_CopyBytes2Mod },                      
    { 0x09, ENTRY_CopyBytes2Mod },                      
    { 0x0A, ENTRY_CopyBytes2Mod },                      
    { 0x0B, ENTRY_CopyBytes2Mod },                      
    { 0x0C, ENTRY_CopyBytes2 },                         
    { 0x0D, ENTRY_CopyBytes3Or5 },                      
#ifdef DETOURS_X64
    { 0x0E, ENTRY_Invalid },                            
#else
    { 0x0E, ENTRY_CopyBytes1 },                         
#endif
    { 0x0F, ENTRY_Copy0F },                             
    { 0x10, ENTRY_CopyBytes2Mod },                      
    { 0x11, ENTRY_CopyBytes2Mod },                      
    { 0x12, ENTRY_CopyBytes2Mod },                      
    { 0x13, ENTRY_CopyBytes2Mod },                      
    { 0x14, ENTRY_CopyBytes2 },                         
    { 0x15, ENTRY_CopyBytes3Or5 },                      
#ifdef DETOURS_X64
    { 0x16, ENTRY_Invalid },                            
    { 0x17, ENTRY_Invalid },                            
#else
    { 0x16, ENTRY_CopyBytes1 },                         
    { 0x17, ENTRY_CopyBytes1 },                         
#endif
    { 0x18, ENTRY_CopyBytes2Mod },                      
    { 0x19, ENTRY_CopyBytes2Mod },                      
    { 0x1A, ENTRY_CopyBytes2Mod },                      
    { 0x1B, ENTRY_CopyBytes2Mod },                      
    { 0x1C, ENTRY_CopyBytes2 },                         
    { 0x1D, ENTRY_CopyBytes3Or5 },                      
#ifdef DETOURS_X64
    { 0x1E, ENTRY_Invalid },                            
    { 0x1F, ENTRY_Invalid },                            
#else
    { 0x1E, ENTRY_CopyBytes1 },                         
    { 0x1F, ENTRY_CopyBytes1 },                         
#endif
    { 0x20, ENTRY_CopyBytes2Mod },                      
    { 0x21, ENTRY_CopyBytes2Mod },                      
    { 0x22, ENTRY_CopyBytes2Mod },                      
    { 0x23, ENTRY_CopyBytes2Mod },                      
    { 0x24, ENTRY_CopyBytes2 },                         
    { 0x25, ENTRY_CopyBytes3Or5 },                      
    { 0x26, ENTRY_CopyBytesSegment },                   
#ifdef DETOURS_X64
    { 0x27, ENTRY_Invalid },                            
#else
    { 0x27, ENTRY_CopyBytes1 },                         
#endif
    { 0x28, ENTRY_CopyBytes2Mod },                      
    { 0x29, ENTRY_CopyBytes2Mod },                      
    { 0x2A, ENTRY_CopyBytes2Mod },                      
    { 0x2B, ENTRY_CopyBytes2Mod },                      
    { 0x2C, ENTRY_CopyBytes2 },                         
    { 0x2D, ENTRY_CopyBytes3Or5 },                      
    { 0x2E, ENTRY_CopyBytesSegment },                   
#ifdef DETOURS_X64
    { 0x2F, ENTRY_Invalid },                            
#else
    { 0x2F, ENTRY_CopyBytes1 },                         
#endif
    { 0x30, ENTRY_CopyBytes2Mod },                      
    { 0x31, ENTRY_CopyBytes2Mod },                      
    { 0x32, ENTRY_CopyBytes2Mod },                      
    { 0x33, ENTRY_CopyBytes2Mod },                      
    { 0x34, ENTRY_CopyBytes2 },                         
    { 0x35, ENTRY_CopyBytes3Or5 },                      
    { 0x36, ENTRY_CopyBytesSegment },                   
#ifdef DETOURS_X64
    { 0x37, ENTRY_Invalid },                            
#else
    { 0x37, ENTRY_CopyBytes1 },                         
#endif
    { 0x38, ENTRY_CopyBytes2Mod },                      
    { 0x39, ENTRY_CopyBytes2Mod },                      
    { 0x3A, ENTRY_CopyBytes2Mod },                      
    { 0x3B, ENTRY_CopyBytes2Mod },                      
    { 0x3C, ENTRY_CopyBytes2 },                         
    { 0x3D, ENTRY_CopyBytes3Or5 },                      
    { 0x3E, ENTRY_CopyBytesSegment },                   
#ifdef DETOURS_X64
    { 0x3F, ENTRY_Invalid },                            
#else
    { 0x3F, ENTRY_CopyBytes1 },                         
#endif
#ifdef DETOURS_X64 
    { 0x40, ENTRY_CopyBytesRax },                       
    { 0x41, ENTRY_CopyBytesRax },                       
    { 0x42, ENTRY_CopyBytesRax },                       
    { 0x43, ENTRY_CopyBytesRax },                       
    { 0x44, ENTRY_CopyBytesRax },                       
    { 0x45, ENTRY_CopyBytesRax },                       
    { 0x46, ENTRY_CopyBytesRax },                       
    { 0x47, ENTRY_CopyBytesRax },                       
    { 0x48, ENTRY_CopyBytesRax },                       
    { 0x49, ENTRY_CopyBytesRax },                       
    { 0x4A, ENTRY_CopyBytesRax },                       
    { 0x4B, ENTRY_CopyBytesRax },                       
    { 0x4C, ENTRY_CopyBytesRax },                       
    { 0x4D, ENTRY_CopyBytesRax },                       
    { 0x4E, ENTRY_CopyBytesRax },                       
    { 0x4F, ENTRY_CopyBytesRax },                       
#else
    { 0x40, ENTRY_CopyBytes1 },                         
    { 0x41, ENTRY_CopyBytes1 },                         
    { 0x42, ENTRY_CopyBytes1 },                         
    { 0x43, ENTRY_CopyBytes1 },                         
    { 0x44, ENTRY_CopyBytes1 },                         
    { 0x45, ENTRY_CopyBytes1 },                         
    { 0x46, ENTRY_CopyBytes1 },                         
    { 0x47, ENTRY_CopyBytes1 },                         
    { 0x48, ENTRY_CopyBytes1 },                         
    { 0x49, ENTRY_CopyBytes1 },                         
    { 0x4A, ENTRY_CopyBytes1 },                         
    { 0x4B, ENTRY_CopyBytes1 },                         
    { 0x4C, ENTRY_CopyBytes1 },                         
    { 0x4D, ENTRY_CopyBytes1 },                         
    { 0x4E, ENTRY_CopyBytes1 },                         
    { 0x4F, ENTRY_CopyBytes1 },                         
#endif
    { 0x50, ENTRY_CopyBytes1 },                         
    { 0x51, ENTRY_CopyBytes1 },                         
    { 0x52, ENTRY_CopyBytes1 },                         
    { 0x53, ENTRY_CopyBytes1 },                         
    { 0x54, ENTRY_CopyBytes1 },                         
    { 0x55, ENTRY_CopyBytes1 },                         
    { 0x56, ENTRY_CopyBytes1 },                         
    { 0x57, ENTRY_CopyBytes1 },                         
    { 0x58, ENTRY_CopyBytes1 },                         
    { 0x59, ENTRY_CopyBytes1 },                         
    { 0x5A, ENTRY_CopyBytes1 },                         
    { 0x5B, ENTRY_CopyBytes1 },                         
    { 0x5C, ENTRY_CopyBytes1 },                         
    { 0x5D, ENTRY_CopyBytes1 },                         
    { 0x5E, ENTRY_CopyBytes1 },                         
    { 0x5F, ENTRY_CopyBytes1 },                         
#ifdef DETOURS_X64
    { 0x60, ENTRY_Invalid },                            
    { 0x61, ENTRY_Invalid },                            
    { 0x62, ENTRY_Invalid },                            
#else
    { 0x60, ENTRY_CopyBytes1 },                         
    { 0x61, ENTRY_CopyBytes1 },                         
    { 0x62, ENTRY_CopyBytes2Mod },                      
#endif
    { 0x63, ENTRY_CopyBytes2Mod },                      
    { 0x64, ENTRY_CopyBytesSegment },                   
    { 0x65, ENTRY_CopyBytesSegment },                   
    { 0x66, ENTRY_Copy66 },                             
    { 0x67, ENTRY_Copy67 },                             
    { 0x68, ENTRY_CopyBytes3Or5 },                      
    { 0x69, ENTRY_CopyBytes2ModOperand },               
    { 0x6A, ENTRY_CopyBytes2 },                         
    { 0x6B, ENTRY_CopyBytes2Mod1 },                     
    { 0x6C, ENTRY_CopyBytes1 },                         
    { 0x6D, ENTRY_CopyBytes1 },                         
    { 0x6E, ENTRY_CopyBytes1 },                         
    { 0x6F, ENTRY_CopyBytes1 },                         
    { 0x70, ENTRY_CopyBytes2Jump },                     
    { 0x71, ENTRY_CopyBytes2Jump },                     
    { 0x72, ENTRY_CopyBytes2Jump },                     
    { 0x73, ENTRY_CopyBytes2Jump },                     
    { 0x74, ENTRY_CopyBytes2Jump },                     
    { 0x75, ENTRY_CopyBytes2Jump },                     
    { 0x76, ENTRY_CopyBytes2Jump },                     
    { 0x77, ENTRY_CopyBytes2Jump },                     
    { 0x78, ENTRY_CopyBytes2Jump },                     
    { 0x79, ENTRY_CopyBytes2Jump },                     
    { 0x7A, ENTRY_CopyBytes2Jump },                     
    { 0x7B, ENTRY_CopyBytes2Jump },                     
    { 0x7C, ENTRY_CopyBytes2Jump },                     
    { 0x7D, ENTRY_CopyBytes2Jump },                     
    { 0x7E, ENTRY_CopyBytes2Jump },                     
    { 0x7F, ENTRY_CopyBytes2Jump },                     
    { 0x80, ENTRY_CopyBytes2Mod1 },                     
    { 0x81, ENTRY_CopyBytes2ModOperand },               
#ifdef DETOURS_X64
    { 0x82, ENTRY_Invalid },                            
#else
    { 0x82, ENTRY_CopyBytes2Mod1 },                     
#endif
    { 0x83, ENTRY_CopyBytes2Mod1 },                     
    { 0x84, ENTRY_CopyBytes2Mod },                      
    { 0x85, ENTRY_CopyBytes2Mod },                      
    { 0x86, ENTRY_CopyBytes2Mod },                      
    { 0x87, ENTRY_CopyBytes2Mod },                      
    { 0x88, ENTRY_CopyBytes2Mod },                      
    { 0x89, ENTRY_CopyBytes2Mod },                      
    { 0x8A, ENTRY_CopyBytes2Mod },                      
    { 0x8B, ENTRY_CopyBytes2Mod },                      
    { 0x8C, ENTRY_CopyBytes2Mod },                      
    { 0x8D, ENTRY_CopyBytes2Mod },                      
    { 0x8E, ENTRY_CopyBytes2Mod },                      
    { 0x8F, ENTRY_CopyBytes2Mod },                      
    { 0x90, ENTRY_CopyBytes1 },                         
    { 0x91, ENTRY_CopyBytes1 },                         
    { 0x92, ENTRY_CopyBytes1 },                         
    { 0x93, ENTRY_CopyBytes1 },                         
    { 0x94, ENTRY_CopyBytes1 },                         
    { 0x95, ENTRY_CopyBytes1 },                         
    { 0x96, ENTRY_CopyBytes1 },                         
    { 0x97, ENTRY_CopyBytes1 },                         
    { 0x98, ENTRY_CopyBytes1 },                         
    { 0x99, ENTRY_CopyBytes1 },                         
#ifdef DETOURS_X64
    { 0x9A, ENTRY_Invalid },                            
#else
    { 0x9A, ENTRY_CopyBytes5Or7Dynamic },               
#endif
    { 0x9B, ENTRY_CopyBytes1 },                         
    { 0x9C, ENTRY_CopyBytes1 },                         
    { 0x9D, ENTRY_CopyBytes1 },                         
    { 0x9E, ENTRY_CopyBytes1 },                         
    { 0x9F, ENTRY_CopyBytes1 },                         
    { 0xA0, ENTRY_CopyBytes1Address },                  
    { 0xA1, ENTRY_CopyBytes1Address },                  
    { 0xA2, ENTRY_CopyBytes1Address },                  
    { 0xA3, ENTRY_CopyBytes1Address },                  
    { 0xA4, ENTRY_CopyBytes1 },                         
    { 0xA5, ENTRY_CopyBytes1 },                         
    { 0xA6, ENTRY_CopyBytes1 },                         
    { 0xA7, ENTRY_CopyBytes1 },                         
    { 0xA8, ENTRY_CopyBytes2 },                         
    { 0xA9, ENTRY_CopyBytes3Or5 },                      
    { 0xAA, ENTRY_CopyBytes1 },                         
    { 0xAB, ENTRY_CopyBytes1 },                         
    { 0xAC, ENTRY_CopyBytes1 },                         
    { 0xAD, ENTRY_CopyBytes1 },                         
    { 0xAE, ENTRY_CopyBytes1 },                         
    { 0xAF, ENTRY_CopyBytes1 },                         
    { 0xB0, ENTRY_CopyBytes2 },                         
    { 0xB1, ENTRY_CopyBytes2 },                         
    { 0xB2, ENTRY_CopyBytes2 },                         
    { 0xB3, ENTRY_CopyBytes2 },                         
    { 0xB4, ENTRY_CopyBytes2 },                         
    { 0xB5, ENTRY_CopyBytes2 },                         
    { 0xB6, ENTRY_CopyBytes2 },                         
    { 0xB7, ENTRY_CopyBytes2 },                         
    { 0xB8, ENTRY_CopyBytes3Or5Rax },                   
    { 0xB9, ENTRY_CopyBytes3Or5Rax },                   
    { 0xBA, ENTRY_CopyBytes3Or5Rax },                   
    { 0xBB, ENTRY_CopyBytes3Or5Rax },                   
    { 0xBC, ENTRY_CopyBytes3Or5Rax },                   
    { 0xBD, ENTRY_CopyBytes3Or5Rax },                   
    { 0xBE, ENTRY_CopyBytes3Or5Rax },                   
    { 0xBF, ENTRY_CopyBytes3Or5Rax },                   
    { 0xC0, ENTRY_CopyBytes2Mod1 },                     
    { 0xC1, ENTRY_CopyBytes2Mod1 },                     
    { 0xC2, ENTRY_CopyBytes3 },                         
    { 0xC3, ENTRY_CopyBytes1 },                         
    { 0xC4, ENTRY_CopyVex3 },                           
    { 0xC5, ENTRY_CopyVex2 },                           
    { 0xC6, ENTRY_CopyBytes2Mod1 },                     
    { 0xC7, ENTRY_CopyBytes2ModOperand },               
    { 0xC8, ENTRY_CopyBytes4 },                         
    { 0xC9, ENTRY_CopyBytes1 },                         
    { 0xCA, ENTRY_CopyBytes3Dynamic },                  
    { 0xCB, ENTRY_CopyBytes1Dynamic },                  
    { 0xCC, ENTRY_CopyBytes1Dynamic },                  
    { 0xCD, ENTRY_CopyBytes2Dynamic },                  
#ifdef DETOURS_X64
    { 0xCE, ENTRY_Invalid },                            
#else
    { 0xCE, ENTRY_CopyBytes1Dynamic },                  
#endif
    { 0xCF, ENTRY_CopyBytes1Dynamic },                  
    { 0xD0, ENTRY_CopyBytes2Mod },                      
    { 0xD1, ENTRY_CopyBytes2Mod },                      
    { 0xD2, ENTRY_CopyBytes2Mod },                      
    { 0xD3, ENTRY_CopyBytes2Mod },                      
#ifdef DETOURS_X64
    { 0xD4, ENTRY_Invalid },                            
    { 0xD5, ENTRY_Invalid },                            
#else
    { 0xD4, ENTRY_CopyBytes2 },                         
    { 0xD5, ENTRY_CopyBytes2 },                         
#endif
    { 0xD6, ENTRY_Invalid },                            
    { 0xD7, ENTRY_CopyBytes1 },                         
    { 0xD8, ENTRY_CopyBytes2Mod },                      
    { 0xD9, ENTRY_CopyBytes2Mod },                      
    { 0xDA, ENTRY_CopyBytes2Mod },                      
    { 0xDB, ENTRY_CopyBytes2Mod },                      
    { 0xDC, ENTRY_CopyBytes2Mod },                      
    { 0xDD, ENTRY_CopyBytes2Mod },                      
    { 0xDE, ENTRY_CopyBytes2Mod },                      
    { 0xDF, ENTRY_CopyBytes2Mod },                      
    { 0xE0, ENTRY_CopyBytes2CantJump },                 
    { 0xE1, ENTRY_CopyBytes2CantJump },                 
    { 0xE2, ENTRY_CopyBytes2CantJump },                 
    { 0xE3, ENTRY_CopyBytes2CantJump },                 
    { 0xE4, ENTRY_CopyBytes2 },                         
    { 0xE5, ENTRY_CopyBytes2 },                         
    { 0xE6, ENTRY_CopyBytes2 },                         
    { 0xE7, ENTRY_CopyBytes2 },                         
    { 0xE8, ENTRY_CopyBytes3Or5Target },                
    { 0xE9, ENTRY_CopyBytes3Or5Target },                
#ifdef DETOURS_X64
    { 0xEA, ENTRY_Invalid },                            
#else
    { 0xEA, ENTRY_CopyBytes5Or7Dynamic },               
#endif
    { 0xEB, ENTRY_CopyBytes2Jump },                     
    { 0xEC, ENTRY_CopyBytes1 },                         
    { 0xED, ENTRY_CopyBytes1 },                         
    { 0xEE, ENTRY_CopyBytes1 },                         
    { 0xEF, ENTRY_CopyBytes1 },                         
    { 0xF0, ENTRY_CopyBytesPrefix },                    
    { 0xF1, ENTRY_CopyBytes1Dynamic },                  
    { 0xF2, ENTRY_CopyF2 },                             

    { 0xF3, ENTRY_CopyF3 },                             





    { 0xF4, ENTRY_CopyBytes1 },                         
    { 0xF5, ENTRY_CopyBytes1 },                         
    { 0xF6, ENTRY_CopyF6 },                             
    { 0xF7, ENTRY_CopyF7 },                             
    { 0xF8, ENTRY_CopyBytes1 },                         
    { 0xF9, ENTRY_CopyBytes1 },                         
    { 0xFA, ENTRY_CopyBytes1 },                         
    { 0xFB, ENTRY_CopyBytes1 },                         
    { 0xFC, ENTRY_CopyBytes1 },                         
    { 0xFD, ENTRY_CopyBytes1 },                         
    { 0xFE, ENTRY_CopyBytes2Mod },                      
    { 0xFF, ENTRY_CopyFF },                             
    { 0, ENTRY_End },
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable0F[257] =
{
#ifdef DETOURS_X86
    { 0x00, ENTRY_Copy0F00 },                           
#else
    { 0x00, ENTRY_CopyBytes2Mod },                      
#endif
    { 0x01, ENTRY_CopyBytes2Mod },                      
    { 0x02, ENTRY_CopyBytes2Mod },                      
    { 0x03, ENTRY_CopyBytes2Mod },                      
    { 0x04, ENTRY_Invalid },                            
    { 0x05, ENTRY_CopyBytes1 },                         
    { 0x06, ENTRY_CopyBytes1 },                         
    { 0x07, ENTRY_CopyBytes1 },                         
    { 0x08, ENTRY_CopyBytes1 },                         
    { 0x09, ENTRY_CopyBytes1 },                         
    { 0x0A, ENTRY_Invalid },                            
    { 0x0B, ENTRY_CopyBytes1 },                         
    { 0x0C, ENTRY_Invalid },                            
    { 0x0D, ENTRY_CopyBytes2Mod },                      
    { 0x0E, ENTRY_CopyBytes1 },                         
    { 0x0F, ENTRY_CopyBytes2Mod1 },                     
    { 0x10, ENTRY_CopyBytes2Mod },                      
    { 0x11, ENTRY_CopyBytes2Mod },                      
    { 0x12, ENTRY_CopyBytes2Mod },                      
    { 0x13, ENTRY_CopyBytes2Mod },                      
    { 0x14, ENTRY_CopyBytes2Mod },                      
    { 0x15, ENTRY_CopyBytes2Mod },                      
    { 0x16, ENTRY_CopyBytes2Mod },                      
    { 0x17, ENTRY_CopyBytes2Mod },                      
    { 0x18, ENTRY_CopyBytes2Mod },                      
    { 0x19, ENTRY_CopyBytes2Mod },                      
    { 0x1A, ENTRY_CopyBytes2Mod },                      
    { 0x1B, ENTRY_CopyBytes2Mod },                      
    { 0x1C, ENTRY_CopyBytes2Mod },                      
    { 0x1D, ENTRY_CopyBytes2Mod },                      
    { 0x1E, ENTRY_CopyBytes2Mod },                      
    { 0x1F, ENTRY_CopyBytes2Mod },                      
    { 0x20, ENTRY_CopyBytes2Mod },                      
    { 0x21, ENTRY_CopyBytes2Mod },                      
    { 0x22, ENTRY_CopyBytes2Mod },                      
    { 0x23, ENTRY_CopyBytes2Mod },                      
#ifdef DETOURS_X64
    { 0x24, ENTRY_Invalid },                            
#else
    { 0x24, ENTRY_CopyBytes2Mod },                      
#endif
    { 0x25, ENTRY_Invalid },                            
#ifdef DETOURS_X64
    { 0x26, ENTRY_Invalid },                            
#else
    { 0x26, ENTRY_CopyBytes2Mod },                      
#endif
    { 0x27, ENTRY_Invalid },                            
    { 0x28, ENTRY_CopyBytes2Mod },                      
    { 0x29, ENTRY_CopyBytes2Mod },                      
    { 0x2A, ENTRY_CopyBytes2Mod },                      
    { 0x2B, ENTRY_CopyBytes2Mod },                      
    { 0x2C, ENTRY_CopyBytes2Mod },                      
    { 0x2D, ENTRY_CopyBytes2Mod },                      
    { 0x2E, ENTRY_CopyBytes2Mod },                      
    { 0x2F, ENTRY_CopyBytes2Mod },                      
    { 0x30, ENTRY_CopyBytes1 },                         
    { 0x31, ENTRY_CopyBytes1 },                         
    { 0x32, ENTRY_CopyBytes1 },                         
    { 0x33, ENTRY_CopyBytes1 },                         
    { 0x34, ENTRY_CopyBytes1 },                         
    { 0x35, ENTRY_CopyBytes1 },                         
    { 0x36, ENTRY_Invalid },                            
    { 0x37, ENTRY_CopyBytes1 },                         
    { 0x38, ENTRY_CopyBytes3Mod },                      
    { 0x39, ENTRY_Invalid },                            
    { 0x3A, ENTRY_CopyBytes3Mod1 },                      
    { 0x3B, ENTRY_Invalid },                            
    { 0x3C, ENTRY_Invalid },                            
    { 0x3D, ENTRY_Invalid },                            
    { 0x3E, ENTRY_Invalid },                            
    { 0x3F, ENTRY_Invalid },                            
    { 0x40, ENTRY_CopyBytes2Mod },                      
    { 0x41, ENTRY_CopyBytes2Mod },                      
    { 0x42, ENTRY_CopyBytes2Mod },                      
    { 0x43, ENTRY_CopyBytes2Mod },                      
    { 0x44, ENTRY_CopyBytes2Mod },                      
    { 0x45, ENTRY_CopyBytes2Mod },                      
    { 0x46, ENTRY_CopyBytes2Mod },                      
    { 0x47, ENTRY_CopyBytes2Mod },                      
    { 0x48, ENTRY_CopyBytes2Mod },                      
    { 0x49, ENTRY_CopyBytes2Mod },                      
    { 0x4A, ENTRY_CopyBytes2Mod },                      
    { 0x4B, ENTRY_CopyBytes2Mod },                      
    { 0x4C, ENTRY_CopyBytes2Mod },                      
    { 0x4D, ENTRY_CopyBytes2Mod },                      
    { 0x4E, ENTRY_CopyBytes2Mod },                      
    { 0x4F, ENTRY_CopyBytes2Mod },                      
    { 0x50, ENTRY_CopyBytes2Mod },                      
    { 0x51, ENTRY_CopyBytes2Mod },                      
    { 0x52, ENTRY_CopyBytes2Mod },                      
    { 0x53, ENTRY_CopyBytes2Mod },                      
    { 0x54, ENTRY_CopyBytes2Mod },                      
    { 0x55, ENTRY_CopyBytes2Mod },                      
    { 0x56, ENTRY_CopyBytes2Mod },                      
    { 0x57, ENTRY_CopyBytes2Mod },                      
    { 0x58, ENTRY_CopyBytes2Mod },                      
    { 0x59, ENTRY_CopyBytes2Mod },                      
    { 0x5A, ENTRY_CopyBytes2Mod },                      
    { 0x5B, ENTRY_CopyBytes2Mod },                      
    { 0x5C, ENTRY_CopyBytes2Mod },                      
    { 0x5D, ENTRY_CopyBytes2Mod },                      
    { 0x5E, ENTRY_CopyBytes2Mod },                      
    { 0x5F, ENTRY_CopyBytes2Mod },                      
    { 0x60, ENTRY_CopyBytes2Mod },                      
    { 0x61, ENTRY_CopyBytes2Mod },                      
    { 0x62, ENTRY_CopyBytes2Mod },                      
    { 0x63, ENTRY_CopyBytes2Mod },                      
    { 0x64, ENTRY_CopyBytes2Mod },                      
    { 0x65, ENTRY_CopyBytes2Mod },                      
    { 0x66, ENTRY_CopyBytes2Mod },                      
    { 0x67, ENTRY_CopyBytes2Mod },                      
    { 0x68, ENTRY_CopyBytes2Mod },                      
    { 0x69, ENTRY_CopyBytes2Mod },                      
    { 0x6A, ENTRY_CopyBytes2Mod },                      
    { 0x6B, ENTRY_CopyBytes2Mod },                      
    { 0x6C, ENTRY_CopyBytes2Mod },                      
    { 0x6D, ENTRY_CopyBytes2Mod },                      
    { 0x6E, ENTRY_CopyBytes2Mod },                      
    { 0x6F, ENTRY_CopyBytes2Mod },                      
    { 0x70, ENTRY_CopyBytes2Mod1 },                     
    { 0x71, ENTRY_CopyBytes2Mod1 },                     
    { 0x72, ENTRY_CopyBytes2Mod1 },                     
    { 0x73, ENTRY_CopyBytes2Mod1 },                     
    { 0x74, ENTRY_CopyBytes2Mod },                      
    { 0x75, ENTRY_CopyBytes2Mod },                      
    { 0x76, ENTRY_CopyBytes2Mod },                      
    { 0x77, ENTRY_CopyBytes1 },                         
    
    { 0x78, ENTRY_Copy0F78 },                           
    
    { 0x79, ENTRY_CopyBytes2Mod },                      
    { 0x7A, ENTRY_Invalid },                            
    { 0x7B, ENTRY_Invalid },                            
    { 0x7C, ENTRY_CopyBytes2Mod },                      
    { 0x7D, ENTRY_CopyBytes2Mod },                      
    { 0x7E, ENTRY_CopyBytes2Mod },                      
    { 0x7F, ENTRY_CopyBytes2Mod },                      
    { 0x80, ENTRY_CopyBytes3Or5Target },                
    { 0x81, ENTRY_CopyBytes3Or5Target },                
    { 0x82, ENTRY_CopyBytes3Or5Target },                
    { 0x83, ENTRY_CopyBytes3Or5Target },                
    { 0x84, ENTRY_CopyBytes3Or5Target },                
    { 0x85, ENTRY_CopyBytes3Or5Target },                
    { 0x86, ENTRY_CopyBytes3Or5Target },                
    { 0x87, ENTRY_CopyBytes3Or5Target },                
    { 0x88, ENTRY_CopyBytes3Or5Target },                
    { 0x89, ENTRY_CopyBytes3Or5Target },                
    { 0x8A, ENTRY_CopyBytes3Or5Target },                
    { 0x8B, ENTRY_CopyBytes3Or5Target },                
    { 0x8C, ENTRY_CopyBytes3Or5Target },                
    { 0x8D, ENTRY_CopyBytes3Or5Target },                
    { 0x8E, ENTRY_CopyBytes3Or5Target },                
    { 0x8F, ENTRY_CopyBytes3Or5Target },                
    { 0x90, ENTRY_CopyBytes2Mod },                      
    { 0x91, ENTRY_CopyBytes2Mod },                      
    { 0x92, ENTRY_CopyBytes2Mod },                      
    { 0x93, ENTRY_CopyBytes2Mod },                      
    { 0x94, ENTRY_CopyBytes2Mod },                      
    { 0x95, ENTRY_CopyBytes2Mod },                      
    { 0x96, ENTRY_CopyBytes2Mod },                      
    { 0x97, ENTRY_CopyBytes2Mod },                      
    { 0x98, ENTRY_CopyBytes2Mod },                      
    { 0x99, ENTRY_CopyBytes2Mod },                      
    { 0x9A, ENTRY_CopyBytes2Mod },                      
    { 0x9B, ENTRY_CopyBytes2Mod },                      
    { 0x9C, ENTRY_CopyBytes2Mod },                      
    { 0x9D, ENTRY_CopyBytes2Mod },                      
    { 0x9E, ENTRY_CopyBytes2Mod },                      
    { 0x9F, ENTRY_CopyBytes2Mod },                      
    { 0xA0, ENTRY_CopyBytes1 },                         
    { 0xA1, ENTRY_CopyBytes1 },                         
    { 0xA2, ENTRY_CopyBytes1 },                         
    { 0xA3, ENTRY_CopyBytes2Mod },                      
    { 0xA4, ENTRY_CopyBytes2Mod1 },                     
    { 0xA5, ENTRY_CopyBytes2Mod },                      
    { 0xA6, ENTRY_CopyBytes2Mod },                      
    { 0xA7, ENTRY_CopyBytes2Mod },                      
    { 0xA8, ENTRY_CopyBytes1 },                         
    { 0xA9, ENTRY_CopyBytes1 },                         
    { 0xAA, ENTRY_CopyBytes1 },                         
    { 0xAB, ENTRY_CopyBytes2Mod },                      
    { 0xAC, ENTRY_CopyBytes2Mod1 },                     
    { 0xAD, ENTRY_CopyBytes2Mod },                      

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    { 0xAE, ENTRY_CopyBytes2Mod },                      
    { 0xAF, ENTRY_CopyBytes2Mod },                      
    { 0xB0, ENTRY_CopyBytes2Mod },                      
    { 0xB1, ENTRY_CopyBytes2Mod },                      
    { 0xB2, ENTRY_CopyBytes2Mod },                      
    { 0xB3, ENTRY_CopyBytes2Mod },                      
    { 0xB4, ENTRY_CopyBytes2Mod },                      
    { 0xB5, ENTRY_CopyBytes2Mod },                      
    { 0xB6, ENTRY_CopyBytes2Mod },                      
    { 0xB7, ENTRY_CopyBytes2Mod },                      
#ifdef DETOURS_X86
    { 0xB8, ENTRY_Copy0FB8 },                           
#else
    { 0xB8, ENTRY_CopyBytes2Mod },                      
#endif
    { 0xB9, ENTRY_Invalid },                            
    { 0xBA, ENTRY_CopyBytes2Mod1 },                     
    { 0xBB, ENTRY_CopyBytes2Mod },                      
    { 0xBC, ENTRY_CopyBytes2Mod },                      
    { 0xBD, ENTRY_CopyBytes2Mod },                      
    { 0xBE, ENTRY_CopyBytes2Mod },                      
    { 0xBF, ENTRY_CopyBytes2Mod },                      
    { 0xC0, ENTRY_CopyBytes2Mod },                      
    { 0xC1, ENTRY_CopyBytes2Mod },                      
    { 0xC2, ENTRY_CopyBytes2Mod1 },                     
    { 0xC3, ENTRY_CopyBytes2Mod },                      
    { 0xC4, ENTRY_CopyBytes2Mod1 },                     
    { 0xC5, ENTRY_CopyBytes2Mod1 },                     
    { 0xC6, ENTRY_CopyBytes2Mod1 },                     
    { 0xC7, ENTRY_CopyBytes2Mod },                      
    { 0xC8, ENTRY_CopyBytes1 },                         
    { 0xC9, ENTRY_CopyBytes1 },                         
    { 0xCA, ENTRY_CopyBytes1 },                         
    { 0xCB, ENTRY_CopyBytes1 },                         
    { 0xCC, ENTRY_CopyBytes1 },                         
    { 0xCD, ENTRY_CopyBytes1 },                         
    { 0xCE, ENTRY_CopyBytes1 },                         
    { 0xCF, ENTRY_CopyBytes1 },                         
    { 0xD0, ENTRY_CopyBytes2Mod },                      
    { 0xD1, ENTRY_CopyBytes2Mod },                      
    { 0xD2, ENTRY_CopyBytes2Mod },                      
    { 0xD3, ENTRY_CopyBytes2Mod },                      
    { 0xD4, ENTRY_CopyBytes2Mod },                      
    { 0xD5, ENTRY_CopyBytes2Mod },                      
    { 0xD6, ENTRY_CopyBytes2Mod },                      
    { 0xD7, ENTRY_CopyBytes2Mod },                      
    { 0xD8, ENTRY_CopyBytes2Mod },                      
    { 0xD9, ENTRY_CopyBytes2Mod },                      
    { 0xDA, ENTRY_CopyBytes2Mod },                      
    { 0xDB, ENTRY_CopyBytes2Mod },                      
    { 0xDC, ENTRY_CopyBytes2Mod },                      
    { 0xDD, ENTRY_CopyBytes2Mod },                      
    { 0xDE, ENTRY_CopyBytes2Mod },                      
    { 0xDF, ENTRY_CopyBytes2Mod },                      
    { 0xE0, ENTRY_CopyBytes2Mod  },                     
    { 0xE1, ENTRY_CopyBytes2Mod },                      
    { 0xE2, ENTRY_CopyBytes2Mod },                      
    { 0xE3, ENTRY_CopyBytes2Mod },                      
    { 0xE4, ENTRY_CopyBytes2Mod },                      
    { 0xE5, ENTRY_CopyBytes2Mod },                      
    { 0xE6, ENTRY_CopyBytes2Mod },                      
    { 0xE7, ENTRY_CopyBytes2Mod },                      
    { 0xE8, ENTRY_CopyBytes2Mod },                      
    { 0xE9, ENTRY_CopyBytes2Mod },                      
    { 0xEA, ENTRY_CopyBytes2Mod },                      
    { 0xEB, ENTRY_CopyBytes2Mod },                      
    { 0xEC, ENTRY_CopyBytes2Mod },                      
    { 0xED, ENTRY_CopyBytes2Mod },                      
    { 0xEE, ENTRY_CopyBytes2Mod },                      
    { 0xEF, ENTRY_CopyBytes2Mod },                      
    { 0xF0, ENTRY_CopyBytes2Mod },                      
    { 0xF1, ENTRY_CopyBytes2Mod },                      
    { 0xF2, ENTRY_CopyBytes2Mod },                      
    { 0xF3, ENTRY_CopyBytes2Mod },                      
    { 0xF4, ENTRY_CopyBytes2Mod },                      
    { 0xF5, ENTRY_CopyBytes2Mod },                      
    { 0xF6, ENTRY_CopyBytes2Mod },                      
    { 0xF7, ENTRY_CopyBytes2Mod },                      
    { 0xF8, ENTRY_CopyBytes2Mod },                      
    { 0xF9, ENTRY_CopyBytes2Mod },                      
    { 0xFA, ENTRY_CopyBytes2Mod },                      
    { 0xFB, ENTRY_CopyBytes2Mod },                      
    { 0xFC, ENTRY_CopyBytes2Mod },                      
    { 0xFD, ENTRY_CopyBytes2Mod },                      
    { 0xFE, ENTRY_CopyBytes2Mod },                      
    { 0xFF, ENTRY_Invalid },                            
    { 0, ENTRY_End },
};

BOOL CDetourDis::SanityCheckSystem()
{
    ULONG n = 0;
    for (; n < 256; n++) {
        REFCOPYENTRY pEntry = &s_rceCopyTable[n];

        if (n != pEntry->nOpcode) {
            ASSERT(n == pEntry->nOpcode);
            return FALSE;
        }
    }
    if (s_rceCopyTable[256].pfCopy != NULL) {
        ASSERT(!"Missing end marker.");
        return FALSE;
    }

    for (n = 0; n < 256; n++) {
        REFCOPYENTRY pEntry = &s_rceCopyTable0F[n];

        if (n != pEntry->nOpcode) {
            ASSERT(n == pEntry->nOpcode);
            return FALSE;
        }
    }
    if (s_rceCopyTable0F[256].pfCopy != NULL) {
        ASSERT(!"Missing end marker.");
        return FALSE;
    }

    return TRUE;
}
#endif 



#ifdef DETOURS_IA64

#if defined(_IA64_) != defined(DETOURS_IA64_OFFLINE_LIBRARY)

const DETOUR_IA64_BUNDLE::DETOUR_IA64_METADATA DETOUR_IA64_BUNDLE::s_rceCopyTable[33] =
{
    { 0x00, M_UNIT,      I_UNIT,      I_UNIT,   },
    { 0x01, M_UNIT,      I_UNIT,      I_UNIT,   },
    { 0x02, M_UNIT,      I_UNIT,      I_UNIT,   },
    { 0x03, M_UNIT,      I_UNIT,      I_UNIT,   },
    { 0x04, M_UNIT,      L_UNIT,      X_UNIT,   },
    { 0x05, M_UNIT,      L_UNIT,      X_UNIT,   },
    { 0x06, 0,           0,           0,        },
    { 0x07, 0,           0,           0,        },
    { 0x08, M_UNIT,      M_UNIT,      I_UNIT,   },
    { 0x09, M_UNIT,      M_UNIT,      I_UNIT,   },
    { 0x0a, M_UNIT,      M_UNIT,      I_UNIT,   },
    { 0x0b, M_UNIT,      M_UNIT,      I_UNIT,   },
    { 0x0c, M_UNIT,      F_UNIT,      I_UNIT,   },
    { 0x0d, M_UNIT,      F_UNIT,      I_UNIT,   },
    { 0x0e, M_UNIT,      M_UNIT,      F_UNIT,   },
    { 0x0f, M_UNIT,      M_UNIT,      F_UNIT,   },
    { 0x10, M_UNIT,      I_UNIT,      B_UNIT,   },
    { 0x11, M_UNIT,      I_UNIT,      B_UNIT,   },
    { 0x12, M_UNIT,      B_UNIT,      B_UNIT,   },
    { 0x13, M_UNIT,      B_UNIT,      B_UNIT,   },
    { 0x14, 0,           0,           0,        },
    { 0x15, 0,           0,           0,        },
    { 0x16, B_UNIT,      B_UNIT,      B_UNIT,   },
    { 0x17, B_UNIT,      B_UNIT,      B_UNIT,   },
    { 0x18, M_UNIT,      M_UNIT,      B_UNIT,   },
    { 0x19, M_UNIT,      M_UNIT,      B_UNIT,   },
    { 0x1a, 0,           0,           0,        },
    { 0x1b, 0,           0,           0,        },
    { 0x1c, M_UNIT,      F_UNIT,      B_UNIT,   },
    { 0x1d, M_UNIT,      F_UNIT,      B_UNIT,   },
    { 0x1e, 0,           0,           0,        },
    { 0x1f, 0,           0,           0,        },
    { 0x00, 0,           0,           0,        },
};













BYTE DETOUR_IA64_BUNDLE::GetTemplate() const
{
    return (data[0] & 0x1f);
}

BYTE DETOUR_IA64_BUNDLE::GetInst0() const
{
    return ((data[5] & 0x3c) >> 2);
}

BYTE DETOUR_IA64_BUNDLE::GetInst1() const
{
    return ((data[10] & 0x78) >> 3);
}

BYTE DETOUR_IA64_BUNDLE::GetInst2() const
{
    return ((data[15] & 0xf0) >> 4);
}

BYTE DETOUR_IA64_BUNDLE::GetUnit(BYTE slot) const
{
    switch (slot) {
    case 0: return GetUnit0();
    case 1: return GetUnit1();
    case 2: return GetUnit2();
    }
    __debugbreak();
    return 0;
}

BYTE DETOUR_IA64_BUNDLE::GetUnit0() const
{
    return s_rceCopyTable[data[0] & 0x1f].nUnit0;
}

BYTE DETOUR_IA64_BUNDLE::GetUnit1() const
{
    return s_rceCopyTable[data[0] & 0x1f].nUnit1;
}

BYTE DETOUR_IA64_BUNDLE::GetUnit2() const
{
    return s_rceCopyTable[data[0] & 0x1f].nUnit2;
}

UINT64 DETOUR_IA64_BUNDLE::GetData0() const
{
    return (((wide[0] & 0x000003ffffffffe0) >> 5));
}

UINT64 DETOUR_IA64_BUNDLE::GetData1() const
{
    return (((wide[0] & 0xffffc00000000000) >> 46) |
            ((wide[1] & 0x000000000007ffff) << 18));
}

UINT64 DETOUR_IA64_BUNDLE::GetData2() const
{
    return (((wide[1] & 0x0fffffffff800000) >> 23));
}

VOID DETOUR_IA64_BUNDLE::SetInst(BYTE slot, BYTE nInst)
{
    switch (slot)
    {
    case 0: SetInst0(nInst); return;
    case 1: SetInst1(nInst); return;
    case 2: SetInst2(nInst); return;
    }
    __debugbreak();
}

VOID DETOUR_IA64_BUNDLE::SetInst0(BYTE nInst)
{
    data[5] = (data[5] & ~0x3c) | ((nInst << 2) & 0x3c);
}

VOID DETOUR_IA64_BUNDLE::SetInst1(BYTE nInst)
{
    data[10] = (data[10] & ~0x78) | ((nInst << 3) & 0x78);
}

VOID DETOUR_IA64_BUNDLE::SetInst2(BYTE nInst)
{
    data[15] = (data[15] & ~0xf0) | ((nInst << 4) & 0xf0);
}

VOID DETOUR_IA64_BUNDLE::SetData(BYTE slot, UINT64 nData)
{
    switch (slot)
    {
    case 0: SetData0(nData); return;
    case 1: SetData1(nData); return;
    case 2: SetData2(nData); return;
    }
    __debugbreak();
}

VOID DETOUR_IA64_BUNDLE::SetData0(UINT64 nData)
{
    wide[0] = (wide[0] & ~0x000003ffffffffe0) | (( nData << 5)  & 0x000003ffffffffe0);
}

VOID DETOUR_IA64_BUNDLE::SetData1(UINT64 nData)
{
    wide[0] = (wide[0] & ~0xffffc00000000000) | ((nData << 46) & 0xffffc00000000000);
    wide[1] = (wide[1] & ~0x000000000007ffff) | ((nData >> 18) & 0x000000000007ffff);
}

VOID DETOUR_IA64_BUNDLE::SetData2(UINT64 nData)
{
    wide[1] = (wide[1] & ~0x0fffffffff800000) | ((nData << 23) & 0x0fffffffff800000);
}

UINT64 DETOUR_IA64_BUNDLE::GetInstruction(BYTE slot) const
{
    switch (slot) {
    case 0: return GetInstruction0();
    case 1: return GetInstruction1();
    case 2: return GetInstruction2();
    }
    __debugbreak();
    return 0;
}

UINT64 DETOUR_IA64_BUNDLE::GetInstruction0() const
{
    
    return GetBits(wide[0], DETOUR_IA64_INSTRUCTION0_OFFSET, DETOUR_IA64_INSTRUCTION_SIZE);
}

UINT64 DETOUR_IA64_BUNDLE::GetInstruction1() const
{
    
    const UINT count0 = 64 - DETOUR_IA64_INSTRUCTION1_OFFSET;
    const UINT count1 = DETOUR_IA64_INSTRUCTION_SIZE - count0;
    return GetBits(wide[0], DETOUR_IA64_INSTRUCTION1_OFFSET, count0) | (GetBits(wide[1], 0, count1) << count0);
}

UINT64 DETOUR_IA64_BUNDLE::GetInstruction2() const
{
    
    return wide[1] >> (64 - DETOUR_IA64_INSTRUCTION_SIZE);
}

void DETOUR_IA64_BUNDLE::SetInstruction(BYTE slot, UINT64 instruction)
{
    switch (slot) {
    case 0: SetInstruction0(instruction); return;
    case 1: SetInstruction1(instruction); return;
    case 2: SetInstruction2(instruction); return;
    }
    __debugbreak();
}

void DETOUR_IA64_BUNDLE::SetInstruction0(UINT64 instruction)
{
    wide[0] = SetBits(wide[0], DETOUR_IA64_INSTRUCTION0_OFFSET, DETOUR_IA64_INSTRUCTION_SIZE, instruction);
}

void DETOUR_IA64_BUNDLE::SetInstruction1(UINT64 instruction)
{
    UINT const count0 = 64 - DETOUR_IA64_INSTRUCTION1_OFFSET;
    UINT const count1 = DETOUR_IA64_INSTRUCTION_SIZE - count0;
    UINT64 const wide0 = SetBits(wide[0], DETOUR_IA64_INSTRUCTION1_OFFSET, count0, instruction);
    UINT64 const wide1 = SetBits(wide[1], 0, count1, instruction >> count0);
    wide[0] = wide0;
    wide[1] = wide1;
}

void DETOUR_IA64_BUNDLE::SetInstruction2(UINT64 instruction)
{
    
    wide[1] = SetBits(wide[1], 64 - DETOUR_IA64_INSTRUCTION_SIZE, DETOUR_IA64_INSTRUCTION_SIZE, instruction);
}

UINT64 DETOUR_IA64_BUNDLE::SignExtend(UINT64 Value, UINT64 Offset)

{
    if ((Value & (((UINT64)1) << (Offset - 1))) == 0)
        return Value;
    UINT64 const new_value = Value | ((~(UINT64)0) << Offset);
    return new_value;
}

UINT64 DETOUR_IA64_BUNDLE::GetBits(UINT64 Value, UINT64 Offset, UINT64 Count)
{
    UINT64 const new_value = (Value >> Offset) & ~(~((UINT64)0) << Count);
    return new_value;
}

UINT64 DETOUR_IA64_BUNDLE::SetBits(UINT64 Value, UINT64 Offset, UINT64 Count, UINT64 Field)
{
    UINT64 const mask = (~((~(UINT64)0) << Count)) << Offset;
    UINT64 const new_value = (Value & ~mask) | ((Field << Offset) & mask);
    return new_value;
}

UINT64 DETOUR_IA64_BUNDLE::GetOpcode(UINT64 instruction)

{
    UINT64 const opcode = GetBits(instruction, DETOUR_IA64_INSTRUCTION_SIZE - 4, 4);
    return opcode;
}

UINT64 DETOUR_IA64_BUNDLE::GetX(UINT64 instruction)

{
    UINT64 const x = GetBits(instruction, 33, 1);
    return x;
}

UINT64 DETOUR_IA64_BUNDLE::GetX3(UINT64 instruction)

{
    UINT64 const x3 = GetBits(instruction, 33, 3);
    return x3;
}

UINT64 DETOUR_IA64_BUNDLE::GetX6(UINT64 instruction)

{
    UINT64 const x6 = GetBits(instruction, 27, 6);
    return x6;
}

UINT64 DETOUR_IA64_BUNDLE::GetImm7a(UINT64 instruction)
{
    UINT64 const imm7a = GetBits(instruction, 6, 7);
    return imm7a;
}

UINT64 DETOUR_IA64_BUNDLE::SetImm7a(UINT64 instruction, UINT64 imm7a)
{
    UINT64 const new_instruction = SetBits(instruction, 6, 7, imm7a);
    return new_instruction;
}

UINT64 DETOUR_IA64_BUNDLE::GetImm13c(UINT64 instruction)
{
    UINT64 const imm13c = GetBits(instruction, 20, 13);
    return imm13c;
}

UINT64 DETOUR_IA64_BUNDLE::SetImm13c(UINT64 instruction, UINT64 imm13c)
{
    UINT64 const new_instruction = SetBits(instruction, 20, 13, imm13c);
    return new_instruction;
}

UINT64 DETOUR_IA64_BUNDLE::GetSignBit(UINT64 instruction)
{
    UINT64 const signBit = GetBits(instruction, 36, 1);
    return signBit;
}

UINT64 DETOUR_IA64_BUNDLE::SetSignBit(UINT64 instruction, UINT64 signBit)
{
    UINT64 const new_instruction = SetBits(instruction, 36, 1, signBit);
    return new_instruction;
}

UINT64 DETOUR_IA64_BUNDLE::GetImm20a(UINT64 instruction)
{
    UINT64 const imm20a = GetBits(instruction, 6, 20);
    return imm20a;
}

UINT64 DETOUR_IA64_BUNDLE::SetImm20a(UINT64 instruction, UINT64 imm20a)
{
    UINT64 const new_instruction = SetBits(instruction, 6, 20, imm20a);
    return new_instruction;
}

UINT64 DETOUR_IA64_BUNDLE::GetImm20b(UINT64 instruction)
{
    UINT64 const imm20b = GetBits(instruction, 13, 20);
    return imm20b;
}

UINT64 DETOUR_IA64_BUNDLE::SetImm20b(UINT64 instruction, UINT64 imm20b)
{
    UINT64 const new_instruction = SetBits(instruction, 13, 20, imm20b);
    return new_instruction;
}

bool DETOUR_IA64_BUNDLE::RelocateInstruction(_Inout_ DETOUR_IA64_BUNDLE* pDst,
                                             _In_ BYTE slot,
                                             _Inout_opt_ DETOUR_IA64_BUNDLE* pBundleExtra) const





















{
    UINT64 const instruction = GetInstruction(slot);
    UINT64 const opcode = GetOpcode(instruction);
    size_t const dest = (size_t)pDst;
    size_t const extra = (size_t)pBundleExtra;

    switch (GetUnit(slot)) {
    case F_UNIT:
        
        if (opcode == 0 && GetX(instruction) == 0 && GetX6(instruction) == 8) {
            goto imm20a;
        }
        return false;

    case M_UNIT:
        
        
        if (opcode == 1) {
            UINT64 const x3 = GetX3(instruction);
            if (x3 == 1 || x3 == 3) {
                goto imm13_7;
            }
        }

        
        
        
        
        if (opcode == 0) {
            UINT64 const x3 = GetX3(instruction);
            if (x3 == 4 || x3 == 5 || x3 == 6 || x3 == 7) {
                goto imm20b;
            }
        }
        return false;
    case I_UNIT:
        
        if (opcode == 0 && GetX3(instruction) == 1) { 
            goto imm13_7;
        }
        return false;
    case B_UNIT:
        
        
        
        if (opcode == 4 || opcode == 5) {
            goto imm20b;
        }
        return false;
    }
    return false;

    UINT64 imm;
    UINT64 new_instruction;

imm13_7:
    imm = SignExtend((GetSignBit(instruction) << 20) | (GetImm13c(instruction) << 7) | GetImm7a(instruction), 21) << 4;
    new_instruction = SetSignBit(SetImm13c(SetImm7a(instruction, (extra - dest) >> 4), (extra - dest) >> 11), extra < dest);
    goto set_brl;

imm20a:
    imm = SignExtend((GetSignBit(instruction) << 20) | GetImm20a(instruction), 21) << 4;
    new_instruction = SetSignBit(SetImm20a(instruction, (extra - dest) >> 4), extra < dest);
    goto set_brl;

imm20b:
    imm = SignExtend((GetSignBit(instruction) << 20) | GetImm20b(instruction), 21) << 4;
    new_instruction = SetSignBit(SetImm20b(instruction, (extra - dest) >> 4), extra < dest);
    goto set_brl;

set_brl:
    if (pBundleExtra != NULL) {
        pDst->SetInstruction(slot, new_instruction);
        pBundleExtra->SetBrl((size_t)this + imm);
    }
    return true;
}

UINT DETOUR_IA64_BUNDLE::RelocateBundle(_Inout_ DETOUR_IA64_BUNDLE* pDst,
                                        _Inout_opt_ DETOUR_IA64_BUNDLE* pBundleExtra) const




{
    UINT nExtraBytes = 0;
    for (BYTE slot = 0; slot < DETOUR_IA64_INSTRUCTIONS_PER_BUNDLE; ++slot) {
        if (!RelocateInstruction(pDst, slot, pBundleExtra)) {
            continue;
        }
        pBundleExtra -= !!pBundleExtra;
        nExtraBytes += sizeof(DETOUR_IA64_BUNDLE);
    }
    return nExtraBytes;
}

BOOL DETOUR_IA64_BUNDLE::IsBrl() const
{
    
    
    
    
    return ((wide[0] & 0x000000000000001e) == 0x0000000000000004 && 
            (wide[1] & 0xe000000000000000) == 0xc000000000000000);  
}

VOID DETOUR_IA64_BUNDLE::SetBrl()
{
    wide[0] = 0x0000000100000005;   
    
    wide[1] = 0xc000000800000000;
}

UINT64 DETOUR_IA64_BUNDLE::GetBrlImm() const
{
    return (
            
            ((wide[1] & 0x00fffff000000000) >> 32) |    
            
            ((wide[0] & 0xffff000000000000) >> 24) |    
            
            ((wide[1] & 0x00000000007fffff) << 40) |    
            
            ((wide[1] & 0x0800000000000000) <<  4)      
           );
}

VOID DETOUR_IA64_BUNDLE::SetBrlImm(UINT64 imm)
{
    wide[0] = ((wide[0] & ~0xffff000000000000) |
               
               ((imm & 0x000000ffff000000) << 24)       
              );
    wide[1] = ((wide[1] & ~0x08fffff0007fffff) |
               
               ((imm & 0x0000000000fffff0) << 32) |     
               
               ((imm & 0x7fffff0000000000) >> 40) |     
               
               ((imm & 0x8000000000000000) >>  4)       
              );
}

UINT64 DETOUR_IA64_BUNDLE::GetBrlTarget() const
{
    return (UINT64)this + GetBrlImm();
}

VOID DETOUR_IA64_BUNDLE::SetBrl(UINT64 target)
{
    UINT64 imm = target - (UINT64)this;
    SetBrl();
    SetBrlImm(imm);
}

VOID DETOUR_IA64_BUNDLE::SetBrlTarget(UINT64 target)
{
    UINT64 imm = target - (UINT64)this;
    SetBrlImm(imm);
}

BOOL DETOUR_IA64_BUNDLE::IsMovlGp() const
{
    
    
    
    return ((wide[0] & 0x00003ffffffffffe) == 0x0000000100000004 &&
            (wide[1] & 0xf000080fff800000) == 0x6000000020000000);
}

UINT64 DETOUR_IA64_BUNDLE::GetMovlGp() const
{
    UINT64 raw = (
                  
                  ((wide[1] & 0x000007f000000000) >> 36) |
                  
                  ((wide[1] & 0x07fc000000000000) >> 43) |
                  
                  ((wide[1] & 0x0003e00000000000) >> 29) |
                  
                  ((wide[1] & 0x0000100000000000) >> 23) |
                  
                  ((wide[0] & 0xffffc00000000000) >> 24) |
                  
                  ((wide[1] & 0x00000000007fffff) << 40) |
                  
                  ((wide[1] & 0x0800000000000000) <<  4)
                 );

    return (INT64)raw;
}

VOID DETOUR_IA64_BUNDLE::SetMovlGp(UINT64 gp)
{
    UINT64 raw = (UINT64)gp;

    wide[0] = (0x0000000100000005 |
               
               ((raw & 0x000000ffffc00000) << 24)
              );
    wide[1] = (
               0x6000000020000000 |
               
               ((raw & 0x0000000000000070) << 36) |
               
               ((raw & 0x000000000000ff80) << 43) |
               
               ((raw & 0x00000000001f0000) << 29) |
               
               ((raw & 0x0000000000200000) << 23) |
               
               ((raw & 0x7fffff0000000000) >> 40) |
               
               ((raw & 0x8000000000000000) >>  4)
              );
}

UINT DETOUR_IA64_BUNDLE::Copy(_Out_ DETOUR_IA64_BUNDLE *pDst,
                              _Inout_opt_ DETOUR_IA64_BUNDLE* pBundleExtra) const
{
    

#pragma warning(suppress:6001) 
    pDst->wide[0] = wide[0];
    pDst->wide[1] = wide[1];

    

    UINT nExtraBytes = RelocateBundle(pDst, pBundleExtra);

    if (GetUnit1() == L_UNIT && IsBrl()) {
        pDst->SetBrlTarget(GetBrlTarget());
    }

    return nExtraBytes;
}

BOOL DETOUR_IA64_BUNDLE::SetNop(BYTE slot)
{
    switch (GetUnit(slot)) {
      case I_UNIT:
      case M_UNIT:
      case F_UNIT:
        SetInst(slot, 0);
        SetData(slot, 0x8000000);
        return true;
      case B_UNIT:
        SetInst(slot, 2);
        SetData(slot, 0);
        return true;
    }
    DebugBreak();
    return false;
}

BOOL DETOUR_IA64_BUNDLE::SetNop0()
{
    return SetNop(0);
}

BOOL DETOUR_IA64_BUNDLE::SetNop1()
{
    return SetNop(1);
}

BOOL DETOUR_IA64_BUNDLE::SetNop2()
{
    return SetNop(2);
}

VOID DETOUR_IA64_BUNDLE::SetStop()
{
    data[0] |= 0x01;
}

#endif 

PVOID WINAPI DetourCopyInstruction(_In_opt_ PVOID pDst,
                                   _Inout_opt_ PVOID *ppDstPool,
                                   _In_ PVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget,
                                   _Out_opt_ LONG *plExtra)
{
    LONG nExtra;
    DETOUR_IA64_BUNDLE bExtra;
    DETOUR_IA64_BUNDLE *pbSrc = (DETOUR_IA64_BUNDLE *)pSrc;
    DETOUR_IA64_BUNDLE *pbDst = pDst ? (DETOUR_IA64_BUNDLE *)pDst : &bExtra;

    plExtra = plExtra ? plExtra : &nExtra;
    *plExtra = 0;

    if (ppTarget != NULL) {
        if (pbSrc->IsBrl()) {
            *ppTarget = (PVOID)pbSrc->GetBrlTarget();
        }
        else {
            *ppTarget = DETOUR_INSTRUCTION_TARGET_NONE;
        }
    }
    *plExtra = (LONG)pbSrc->Copy(pbDst, ppDstPool ? ((DETOUR_IA64_BUNDLE*)*ppDstPool) - 1 : (DETOUR_IA64_BUNDLE*)NULL);
    return pbSrc + 1;
}

#endif 

#ifdef DETOURS_ARM

#define DETOURS_PFUNC_TO_PBYTE(p)  ((PBYTE)(((ULONG_PTR)(p)) & ~(ULONG_PTR)1))
#define DETOURS_PBYTE_TO_PFUNC(p)  ((PBYTE)(((ULONG_PTR)(p)) | (ULONG_PTR)1))

#define c_PCAdjust  4       
#define c_PC        15      
#define c_LR        14      
#define c_SP        13      
#define c_NOP       0xbf00  
#define c_BREAK     0xdefe  

class CDetourDis
{
  public:
    CDetourDis();

    PBYTE   CopyInstruction(PBYTE pDst,
                            PBYTE *ppDstPool,
                            PBYTE pSrc,
                            PBYTE *ppTarget,
                            LONG *plExtra);

  public:
    typedef BYTE (CDetourDis::* COPYFUNC)(PBYTE pbDst, PBYTE pbSrc);

    struct COPYENTRY {
        USHORT      nOpcode;
        COPYFUNC    pfCopy;
    };

    typedef const COPYENTRY * REFCOPYENTRY;

    struct Branch5
    {
        DWORD Register : 3;
        DWORD Imm5 : 5;
        DWORD Padding : 1;
        DWORD I : 1;
        DWORD OpCode : 6;
    };

    struct Branch5Target
    {
        DWORD Padding : 1;
        DWORD Imm5 : 5;
        DWORD I : 1;
        DWORD Padding2 : 25;
    };

    struct Branch8
    {
        DWORD Imm8 : 8;
        DWORD Condition : 4;
        DWORD OpCode : 4;
    };

    struct Branch8Target
    {
        DWORD Padding : 1;
        DWORD Imm8 : 8;
        DWORD Padding2 : 23;
    };

    struct Branch11
    {
        DWORD Imm11 : 11;
        DWORD OpCode : 5;
    };

    struct Branch11Target
    {
        DWORD Padding : 1;
        DWORD Imm11 : 11;
        DWORD Padding2 : 20;
    };

    struct Branch20
    {
        DWORD Imm11 : 11;
        DWORD J2 : 1;
        DWORD IT : 1;
        DWORD J1 : 1;
        DWORD Other : 2;
        DWORD Imm6 : 6;
        DWORD Condition : 4;
        DWORD Sign : 1;
        DWORD OpCode : 5;
    };

    struct Branch20Target
    {
        DWORD Padding : 1;
        DWORD Imm11 : 11;
        DWORD Imm6 : 6;
        DWORD J1 : 1;
        DWORD J2 : 1;
        DWORD Sign : 1;
        INT32 Padding2 : 11;
    };

    struct Branch24
    {
        DWORD Imm11             : 11;
        DWORD J2                : 1;
        DWORD InstructionSet    : 1;
        DWORD J1                : 1;
        DWORD Link              : 1;
        DWORD Branch            : 1;
        DWORD Imm10             : 10;
        DWORD Sign              : 1;
        DWORD OpCode            : 5;
    };

    struct Branch24Target
    {
        DWORD Padding : 1;
        DWORD Imm11 : 11;
        DWORD Imm10 : 10;
        DWORD I2 : 1;
        DWORD I1 : 1;
        DWORD Sign : 1;
        INT32 Padding2 : 7;
    };

    struct LiteralLoad8
    {
        DWORD Imm8 : 8;
        DWORD Register : 3;
        DWORD OpCode : 5;
    };

    struct LiteralLoad8Target
    {
        DWORD Padding : 2;
        DWORD Imm8 : 8;
        DWORD Padding2 : 22;
    };

    struct LiteralLoad12
    {
        DWORD Imm12 : 12;
        DWORD Register : 4;
        DWORD OpCodeSuffix : 7;
        DWORD Add : 1;
        DWORD OpCodePrefix : 8;
    };

    struct LiteralLoad12Target
    {
        DWORD Imm12 : 12;
        DWORD Padding : 20;
    };

    struct ImmediateRegisterLoad32
    {
        DWORD Imm12 : 12;
        DWORD DestinationRegister : 4;
        DWORD SourceRegister: 4;
        DWORD OpCode : 12;
    };

    struct ImmediateRegisterLoad16
    {
        DWORD DestinationRegister : 3;
        DWORD SourceRegister: 3;
        DWORD OpCode : 10;
    };

    struct TableBranch
    {
        DWORD IndexRegister : 4;
        DWORD HalfWord : 1;
        DWORD OpCodeSuffix : 11;
        DWORD BaseRegister : 4;
        DWORD OpCodePrefix : 12;
    };

    struct Shift
    {
        DWORD Imm2 : 2;
        DWORD Imm3 : 3;
    };

    struct Add32
    {
        DWORD SecondOperandRegister : 4;
        DWORD Type : 2;
        DWORD Imm2 : 2;
        DWORD DestinationRegister : 4;
        DWORD Imm3 : 3;
        DWORD Padding : 1;
        DWORD FirstOperandRegister : 4;
        DWORD SetFlags : 1;
        DWORD OpCode : 11;
    };

    struct LogicalShiftLeft32
    {
        DWORD SourceRegister : 4;
        DWORD Padding : 2;
        DWORD Imm2 : 2;
        DWORD DestinationRegister : 4;
        DWORD Imm3 : 3;
        DWORD Padding2 : 5;
        DWORD SetFlags : 1;
        DWORD OpCode : 11;
    };

    struct StoreImmediate12
    {
        DWORD Imm12 : 12;
        DWORD SourceRegister : 4;
        DWORD BaseRegister : 4;
        DWORD OpCode : 12;
    };

  protected:
    BYTE    PureCopy16(BYTE* pSource, BYTE* pDest);
    BYTE    PureCopy32(BYTE* pSource, BYTE* pDest);
    BYTE    CopyMiscellaneous16(BYTE* pSource, BYTE* pDest);
    BYTE    CopyConditionalBranchOrOther16(BYTE* pSource, BYTE* pDest);
    BYTE    CopyUnConditionalBranch16(BYTE* pSource, BYTE* pDest);
    BYTE    CopyLiteralLoad16(BYTE* pSource, BYTE* pDest);
    BYTE    CopyBranchExchangeOrDataProcessing16(BYTE* pSource, BYTE* pDest);
    BYTE    CopyBranch24(BYTE* pSource, BYTE* pDest);
    BYTE    CopyBranchOrMiscellaneous32(BYTE* pSource, BYTE* pDest);
    BYTE    CopyLiteralLoad32(BYTE* pSource, BYTE* pDest);
    BYTE    CopyLoadAndStoreSingle(BYTE* pSource, BYTE* pDest);
    BYTE    CopyLoadAndStoreMultipleAndSRS(BYTE* pSource, BYTE* pDest);
    BYTE    CopyTableBranch(BYTE* pSource, BYTE* pDest);
    BYTE    BeginCopy32(BYTE* pSource, BYTE* pDest);

    LONG    DecodeBranch5(ULONG opcode);
    USHORT  EncodeBranch5(ULONG originalOpCode, LONG delta);
    LONG    DecodeBranch8(ULONG opcode);
    USHORT  EncodeBranch8(ULONG originalOpCode, LONG delta);
    LONG    DecodeBranch11(ULONG opcode);
    USHORT  EncodeBranch11(ULONG originalOpCode, LONG delta);
    BYTE    EmitBranch11(PUSHORT& pDest, LONG relativeAddress);
    LONG    DecodeBranch20(ULONG opcode);
    ULONG   EncodeBranch20(ULONG originalOpCode, LONG delta);
    LONG    DecodeBranch24(ULONG opcode, BOOL& fLink);
    ULONG   EncodeBranch24(ULONG originalOpCode, LONG delta, BOOL fLink);
    LONG    DecodeLiteralLoad8(ULONG instruction);
    LONG    DecodeLiteralLoad12(ULONG instruction);
    BYTE    EmitLiteralLoad8(PUSHORT& pDest, BYTE targetRegister, PBYTE pLiteral);
    BYTE    EmitLiteralLoad12(PUSHORT& pDest, BYTE targetRegister, PBYTE pLiteral);
    BYTE    EmitImmediateRegisterLoad32(PUSHORT& pDest, BYTE reg);
    BYTE    EmitImmediateRegisterLoad16(PUSHORT& pDest, BYTE reg);
    BYTE    EmitLongLiteralLoad(PUSHORT& pDest, BYTE reg, PVOID pTarget);
    BYTE    EmitLongBranch(PUSHORT& pDest, PVOID pTarget);
    USHORT  CalculateExtra(BYTE sourceLength, BYTE* pDestStart, BYTE* pDestEnd);

  protected:
    ULONG GetLongInstruction(BYTE* pSource)
    {
        return (((PUSHORT)pSource)[0] << 16) | (((PUSHORT)pSource)[1]);
    }

    BYTE EmitLongInstruction(PUSHORT& pDstInst, ULONG instruction)
    {
        *pDstInst++ = (USHORT)(instruction >> 16);
        *pDstInst++ = (USHORT)instruction;
        return sizeof(ULONG);
    }

    BYTE EmitShortInstruction(PUSHORT& pDstInst, USHORT instruction)
    {
        *pDstInst++ = instruction;
        return sizeof(USHORT);
    }

    PBYTE Align4(PBYTE pValue)
    {
        return (PBYTE)(((size_t)pValue) & ~(ULONG)3u);
    }

    PBYTE CalculateTarget(PBYTE pSource, LONG delta)
    {
        return (pSource + delta + c_PCAdjust);
    }

    LONG CalculateNewDelta(PBYTE pTarget, BYTE* pDest)
    {
        return (LONG)(pTarget - (pDest + c_PCAdjust));
    }

    BYTE    EmitAdd32(PUSHORT& pDstInst, BYTE op1Reg, BYTE op2Reg, BYTE dstReg, BYTE shiftAmount)
    {
        Shift& shift = (Shift&)(shiftAmount);
        const BYTE shiftType = 0x00; 
        Add32 add = { op2Reg, shiftType, shift.Imm2, dstReg, shift.Imm3,
                      0x0, op1Reg, 0x0, 0x758 };
        return EmitLongInstruction(pDstInst, (ULONG&)add);
    }

    BYTE    EmitLogicalShiftLeft32(PUSHORT& pDstInst, BYTE srcReg, BYTE dstReg, BYTE shiftAmount)
    {
        Shift& shift = (Shift&)(shiftAmount);
        LogicalShiftLeft32 shiftLeft = { srcReg, 0x00, shift.Imm2, dstReg, shift.Imm3, 0x1E,
                                         0x00, 0x752 };
        return EmitLongInstruction(pDstInst, (ULONG&)shiftLeft);
    }

    BYTE    EmitStoreImmediate12(PUSHORT& pDstInst, BYTE srcReg, BYTE baseReg, USHORT offset)
    {
        StoreImmediate12 store = { offset, srcReg, baseReg, 0xF8C };
        return EmitLongInstruction(pDstInst, (ULONG&)store);
    }

  protected:
    PBYTE   m_pbTarget;
    PBYTE   m_pbPool;
    LONG    m_lExtra;

    BYTE    m_rbScratchDst[64];

    static const COPYENTRY s_rceCopyTable[33];
};

LONG CDetourDis::DecodeBranch5(ULONG opcode)
{
    Branch5& branch = (Branch5&)(opcode);

    Branch5Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm5 = branch.Imm5;
    target.I = branch.I;

    
    return (LONG&)target;
}

USHORT CDetourDis::EncodeBranch5(ULONG originalOpCode, LONG delta)
{
    
    if (delta < 0 || delta > 0x7F) {
        return 0;
    }

    Branch5& branch = (Branch5&)(originalOpCode);
    Branch5Target& target = (Branch5Target&)(delta);

    branch.Imm5 = target.Imm5;
    branch.I = target.I;

    return (USHORT&)branch;
}

LONG CDetourDis::DecodeBranch8(ULONG opcode)
{
    Branch8& branch = (Branch8&)(opcode);

    Branch8Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm8 = branch.Imm8;

    
    return (((LONG&)target) << 23) >> 23;
}

USHORT CDetourDis::EncodeBranch8(ULONG originalOpCode, LONG delta)
{
    
    if (delta < (-(int)0x100) || delta > 0xFF) {
        return 0;
    }

    Branch8& branch = (Branch8&)(originalOpCode);
    Branch8Target& target = (Branch8Target&)(delta);

    branch.Imm8 = target.Imm8;

    return (USHORT&)branch;
}

LONG CDetourDis::DecodeBranch11(ULONG opcode)
{
    Branch11& branch = (Branch11&)(opcode);

    Branch11Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm11 = branch.Imm11;

    
    return (((LONG&)target) << 20) >> 20;
}

USHORT CDetourDis::EncodeBranch11(ULONG originalOpCode, LONG delta)
{
    
    if (delta < (-(int)0x800) || delta > 0x7FF) {
        return 0;
    }

    Branch11& branch = (Branch11&)(originalOpCode);
    Branch11Target& target = (Branch11Target&)(delta);

    branch.Imm11 = target.Imm11;

    return (USHORT&)branch;
}

BYTE CDetourDis::EmitBranch11(PUSHORT& pDest, LONG relativeAddress)
{
    Branch11Target& target = (Branch11Target&)(relativeAddress);
    Branch11 branch11 = { target.Imm11, 0x1C };

    *pDest++ = (USHORT&)branch11;
    return sizeof(USHORT);
}

LONG CDetourDis::DecodeBranch20(ULONG opcode)
{
    Branch20& branch = (Branch20&)(opcode);

    Branch20Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm11 = branch.Imm11;
    target.Imm6 = branch.Imm6;
    target.Sign = branch.Sign;
    target.J1 = branch.J1;
    target.J2 = branch.J2;

    
    if (target.Sign) {
        target.Padding2 = -1;
    }

    return (LONG&)target;
}

ULONG CDetourDis::EncodeBranch20(ULONG originalOpCode, LONG delta)
{
    
    if (delta < (-(int)0x100000) || delta > 0xFFFFF) {
        return 0;
    }

    Branch20& branch = (Branch20&)(originalOpCode);
    Branch20Target& target = (Branch20Target&)(delta);

    branch.Imm11 = target.Imm11;
    branch.Imm6 = target.Imm6;
    branch.Sign = target.Sign;
    branch.J1 = target.J1;
    branch.J2 = target.J2;

    return (ULONG&)branch;
}

LONG CDetourDis::DecodeBranch24(ULONG opcode, BOOL& fLink)
{
    Branch24& branch = (Branch24&)(opcode);

    Branch24Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm11 = branch.Imm11;
    target.Imm10 = branch.Imm10;
    target.Sign = branch.Sign;
    target.I1 = ~(branch.J1 ^ target.Sign);
    target.I2 = ~(branch.J2 ^ target.Sign);
    fLink = branch.Link;

    
    if (target.Sign) {
        target.Padding2 = -1;
    }

    return (LONG&)target;
}

ULONG CDetourDis::EncodeBranch24(ULONG originalOpCode, LONG delta, BOOL fLink)
{
    
    if (delta < static_cast<int>(0xFF000000) || delta > static_cast<int>(0xFFFFFF)) {
        return 0;
    }

    Branch24& branch = (Branch24&)(originalOpCode);
    Branch24Target& target = (Branch24Target&)(delta);

    branch.Imm11 = target.Imm11;
    branch.Imm10 = target.Imm10;
    branch.Link = fLink;
    branch.Sign = target.Sign;
    branch.J1 = ~(target.I1 ^ branch.Sign);
    branch.J2 = ~(target.I2 ^ branch.Sign);

    return (ULONG&)branch;
}

LONG CDetourDis::DecodeLiteralLoad8(ULONG instruction)
{
    LiteralLoad8& load = (LiteralLoad8&)(instruction);

    LiteralLoad8Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm8 = load.Imm8;

    return (LONG&)target;
}

BYTE CDetourDis::EmitLiteralLoad8(PUSHORT& pDest, BYTE targetRegister, PBYTE pLiteral)
{
    
    
    LONG newDelta = CalculateNewDelta((PBYTE)pLiteral + 2, (PBYTE)pDest);
    LONG relative = ((newDelta > 0 ? newDelta : -newDelta) & 0x3FF);

    LiteralLoad8Target& target = (LiteralLoad8Target&)(relative);
    LiteralLoad8 load = { target.Imm8, targetRegister, 0x9 };

    return EmitShortInstruction(pDest, (USHORT&)load);
}

LONG CDetourDis::DecodeLiteralLoad12(ULONG instruction)
{
    LiteralLoad12& load = (LiteralLoad12&)(instruction);

    LiteralLoad12Target target;
    ZeroMemory(&target, sizeof(target));
    target.Imm12 = load.Imm12;

    return (LONG&)target;
}

BYTE CDetourDis::EmitLiteralLoad12(PUSHORT& pDest, BYTE targetRegister, PBYTE pLiteral)
{
    
    
    LONG newDelta = CalculateNewDelta((PBYTE)pLiteral + 2, (PBYTE)pDest);
    LONG relative = ((newDelta > 0 ? newDelta : -newDelta) & 0xFFF);

    LiteralLoad12Target& target = (LiteralLoad12Target&)(relative);
    target.Imm12 -= target.Imm12 & 3;
    LiteralLoad12 load = { target.Imm12, targetRegister, 0x5F, (DWORD)(newDelta > 0),  0xF8 };

    return EmitLongInstruction(pDest, (ULONG&)load);
}

BYTE CDetourDis::EmitImmediateRegisterLoad32(PUSHORT& pDest, BYTE reg)
{
    ImmediateRegisterLoad32 load = { 0, reg, reg, 0xF8D };
    return EmitLongInstruction(pDest, (ULONG&)load);
}

BYTE CDetourDis::EmitImmediateRegisterLoad16(PUSHORT& pDest, BYTE reg)
{
    ImmediateRegisterLoad16 load = { reg, reg, 0x680 >> 2 };
    return EmitShortInstruction(pDest, (USHORT&)load);
}

BYTE CDetourDis::EmitLongLiteralLoad(PUSHORT& pDest, BYTE targetRegister, PVOID pTarget)
{
    *--((PULONG&)m_pbPool) = (ULONG)(size_t)pTarget;

    
    BYTE size = EmitLiteralLoad12(pDest, targetRegister, m_pbPool);

    
    
    if (targetRegister != c_PC) {
        
        if (targetRegister <= 7) {
            size = (BYTE)(size + EmitImmediateRegisterLoad16(pDest, targetRegister));
        }
        else {
            size = (BYTE)(size + EmitImmediateRegisterLoad32(pDest, targetRegister));
        }
    }

    return size;
}

BYTE CDetourDis::EmitLongBranch(PUSHORT& pDest, PVOID pTarget)
{
    
    BYTE size = EmitLongLiteralLoad(pDest, c_PC, DETOURS_PBYTE_TO_PFUNC(pTarget));
    return size;
}

BYTE CDetourDis::PureCopy16(BYTE* pSource, BYTE* pDest)
{
    *(USHORT *)pDest = *(USHORT *)pSource;
    return sizeof(USHORT);
}

BYTE CDetourDis::PureCopy32(BYTE* pSource, BYTE* pDest)
{
    *(UNALIGNED ULONG *)pDest = *(UNALIGNED ULONG*)pSource;
    return sizeof(DWORD);
}

USHORT CDetourDis::CalculateExtra(BYTE sourceLength, BYTE* pDestStart, BYTE* pDestEnd)
{
    ULONG destinationLength = (ULONG)(pDestEnd - pDestStart);
    return static_cast<USHORT>((destinationLength > sourceLength) ? (destinationLength - sourceLength) : 0);
}

BYTE CDetourDis::CopyMiscellaneous16(BYTE* pSource, BYTE* pDest)
{
    USHORT instruction = *(PUSHORT)(pSource);

    
    if ((instruction & 0x100) && !(instruction & 0x400)) { 
        LONG oldDelta = DecodeBranch5(instruction);
        PBYTE pTarget = CalculateTarget(pSource, oldDelta);
        m_pbTarget = pTarget;

        LONG newDelta = CalculateNewDelta(pTarget, pDest);
        instruction = EncodeBranch5(instruction, newDelta);

        if (instruction) {
            
            *(PUSHORT)(pDest) = instruction;
            return sizeof(USHORT); 
        }

        
        
        
        
        
        
        
        
        
        

        
        PUSHORT pDstInst = (PUSHORT)(pDest);
        PUSHORT pConditionalBranchInstruction = pDstInst++;

        
        BYTE longBranchSize = EmitLongBranch(pDstInst, pTarget);

        
        
        
        instruction = EncodeBranch5(*(PUSHORT)(pSource), longBranchSize - c_PCAdjust + sizeof(USHORT));
        Branch5& branch = (Branch5&)(instruction);
        branch.OpCode = (branch.OpCode & 0x02) ? 0x2C : 0x2E; 
        *pConditionalBranchInstruction = instruction;

        
        m_lExtra = CalculateExtra(sizeof(USHORT), pDest, (BYTE*)(pDstInst));
        return sizeof(USHORT); 
    }

    
    if ((instruction >> 8 == 0xBF) && (instruction & 0xF)) { 
        
        ASSERT(false);
        return sizeof(USHORT);
    }

    
    return PureCopy16(pSource, pDest);
}

BYTE CDetourDis::CopyConditionalBranchOrOther16(BYTE* pSource, BYTE* pDest)
{
    USHORT instruction = *(PUSHORT)(pSource);

    
    
    if ((instruction & 0xE00) != 0xE00) { 
        LONG oldDelta = DecodeBranch8(instruction);
        PBYTE pTarget = CalculateTarget(pSource, oldDelta);
        m_pbTarget = pTarget;

        LONG newDelta = CalculateNewDelta(pTarget, pDest);
        instruction = EncodeBranch8(instruction, newDelta);
        if (instruction) {
            
            *(PUSHORT)(pDest) = instruction;
            return sizeof(USHORT); 
        }

        
        
        
        
        
        
        
        
        
        
        

        
        USHORT newInstruction = EncodeBranch8(*(PUSHORT)(pSource), 0); 
        ASSERT(newInstruction);
        PUSHORT pDstInst = (PUSHORT)(pDest);
        *pDstInst++ = newInstruction;

        
        
        PUSHORT pUnconditionalBranchInstruction = pDstInst++;

        
        BYTE longBranchSize = EmitLongBranch(pDstInst, pTarget);

        
        Branch11 branch11 = { 0x00, 0x1C };
        newInstruction = EncodeBranch11(*(DWORD*)(&branch11), longBranchSize - c_PCAdjust + sizeof(USHORT));
        ASSERT(newInstruction);
        *pUnconditionalBranchInstruction = newInstruction;

        
        m_lExtra = CalculateExtra(sizeof(USHORT), pDest, (BYTE*)(pDstInst));
        return sizeof(USHORT); 
    }

    return PureCopy16(pSource, pDest);
}

BYTE CDetourDis::CopyUnConditionalBranch16(BYTE* pSource, BYTE* pDest)
{
    ULONG instruction = *(PUSHORT)(pSource);

    LONG oldDelta = DecodeBranch11(instruction);
    PBYTE pTarget = CalculateTarget(pSource, oldDelta);
    m_pbTarget = pTarget;

    LONG newDelta = CalculateNewDelta(pTarget, pDest);
    instruction = EncodeBranch11(instruction, newDelta);
    if (instruction) {
        
        *(PUSHORT)(pDest) = (USHORT)instruction;
        return sizeof(USHORT); 
    }

    
    PUSHORT pDstInst = (PUSHORT)(pDest);
    instruction = EncodeBranch24(0xf0009000, newDelta, FALSE);
    if (instruction) {
        
        EmitLongInstruction(pDstInst, instruction);

        m_lExtra = sizeof(DWORD) - sizeof(USHORT); 
        return sizeof(USHORT); 
    }

    
    if (!instruction) {
        
        
        
        
        
        EmitLongBranch(pDstInst, pTarget);

        
        m_lExtra = CalculateExtra(sizeof(USHORT), pDest, (BYTE*)(pDstInst));
        return sizeof(USHORT); 
    }

    return sizeof(USHORT); 
}

BYTE CDetourDis::CopyLiteralLoad16(BYTE* pSource, BYTE* pDest)
{
    PBYTE pStart = pDest;
    USHORT instruction = *(PUSHORT)(pSource);

    LONG oldDelta = DecodeLiteralLoad8(instruction);
    PBYTE pTarget = CalculateTarget(Align4(pSource), oldDelta);

    
    
    
    
    
    LiteralLoad8& load8 = (LiteralLoad8&)(instruction);
    EmitLongLiteralLoad((PUSHORT&)pDest, load8.Register, pTarget);

    m_lExtra = (LONG)(pDest - pStart - sizeof(USHORT));
    return sizeof(USHORT); 
}

BYTE CDetourDis::CopyBranchExchangeOrDataProcessing16(BYTE* pSource, BYTE* pDest)
{
    ULONG instruction = *(PUSHORT)(pSource);

    
    if ((instruction & 0xff80) == 0x4700) {
        
        m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }

    
    return PureCopy16(pSource, pDest);
}

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable[33] =
{
    
    
     { 0x00, &CDetourDis::PureCopy16 },
     { 0x01, &CDetourDis::PureCopy16 },
     { 0x02, &CDetourDis::PureCopy16 },

    
    
     { 0x03, &CDetourDis::PureCopy16},

    
     { 0x04, &CDetourDis::PureCopy16 },
     { 0x05, &CDetourDis::PureCopy16 },
     { 0x06, &CDetourDis::PureCopy16 },
     { 0x07, &CDetourDis::PureCopy16 },

    
    
    
     { 0x08, &CDetourDis::CopyBranchExchangeOrDataProcessing16 },

    
     { 0x09, &CDetourDis::CopyLiteralLoad16 },

    
     { 0x0a, &CDetourDis::PureCopy16 },
     { 0x0b, &CDetourDis::PureCopy16 },

    
     { 0x0c, &CDetourDis::PureCopy16 },
     { 0x0d, &CDetourDis::PureCopy16 },
     { 0x0e, &CDetourDis::PureCopy16 },
     { 0x0f, &CDetourDis::PureCopy16 },

    
     { 0x10, &CDetourDis::PureCopy16 },
     { 0x11, &CDetourDis::PureCopy16 },

    
     { 0x12, &CDetourDis::PureCopy16 },
     { 0x13, &CDetourDis::PureCopy16 },

    
     { 0x14, &CDetourDis::PureCopy16 },
    
    
    
     { 0x15, &CDetourDis::PureCopy16 },

    
     { 0x16, &CDetourDis::CopyMiscellaneous16 },
     { 0x17, &CDetourDis::CopyMiscellaneous16 },

    
     { 0x18, &CDetourDis::PureCopy16 },
     { 0x19, &CDetourDis::PureCopy16 },
    
    
    

    
     { 0x1a, &CDetourDis::CopyConditionalBranchOrOther16 },

    
    
    
     { 0x1b, &CDetourDis::CopyConditionalBranchOrOther16 },

    
     { 0x1c, &CDetourDis::CopyUnConditionalBranch16 },

    
     { 0x1d, &CDetourDis::BeginCopy32 },
     { 0x1e, &CDetourDis::BeginCopy32 },
     { 0x1f, &CDetourDis::BeginCopy32 },
    { 0, NULL }
};

BYTE CDetourDis::CopyBranch24(BYTE* pSource, BYTE* pDest)
{
    ULONG instruction = GetLongInstruction(pSource);
    BOOL fLink;
    LONG oldDelta = DecodeBranch24(instruction, fLink);
    PBYTE pTarget = CalculateTarget(pSource, oldDelta);
    m_pbTarget = pTarget;

    
    PUSHORT pDstInst = (PUSHORT)(pDest);
    LONG newDelta = CalculateNewDelta(pTarget, pDest);
    instruction = EncodeBranch24(instruction, newDelta, fLink);
    if (instruction) {
        
        EmitLongInstruction(pDstInst, instruction);
        return sizeof(DWORD);
    }

    
    EmitLongBranch(pDstInst, pTarget);

    
    m_lExtra = CalculateExtra(sizeof(DWORD), pDest, (BYTE*)(pDstInst));
    return sizeof(DWORD); 
}

BYTE CDetourDis::CopyBranchOrMiscellaneous32(BYTE* pSource, BYTE* pDest)
{
    ULONG instruction = GetLongInstruction(pSource);
    if ((instruction & 0xf800d000) == 0xf0008000) { 
        LONG oldDelta = DecodeBranch20(instruction);
        PBYTE pTarget = CalculateTarget(pSource, oldDelta);
        m_pbTarget = pTarget;

        
        PUSHORT pDstInst = (PUSHORT)(pDest);
        LONG newDelta = CalculateNewDelta(pTarget, pDest);
        instruction = EncodeBranch20(instruction, newDelta);
        if (instruction) {
            
            EmitLongInstruction(pDstInst, instruction);
            return sizeof(DWORD);
        }

        
        
        
        
        
        
        
        
        
        

        
        
        instruction = EncodeBranch20(GetLongInstruction(pSource), 2);
        
        
        ASSERT(instruction);
        EmitLongInstruction(pDstInst, instruction);

        
        
        
        
        
        PUSHORT pUnconditionalBranchInstruction = pDstInst++;

        
        BYTE longBranchSize = EmitLongBranch(pDstInst, pTarget);

        
        
        Branch11 branch11 = { 0x00, 0x1C };
        instruction = EncodeBranch11(*(DWORD*)(&branch11), longBranchSize - c_PCAdjust + sizeof(USHORT));
        ASSERT(instruction);
        *pUnconditionalBranchInstruction = static_cast<USHORT>(instruction);

        
        m_lExtra = CalculateExtra(sizeof(DWORD), pDest, (BYTE*)(pDstInst));
        return sizeof(DWORD); 
    }

    if ((instruction & 0xf800d000) == 0xf0009000) { 
        
        return CopyBranch24(pSource, pDest);
    }

    if ((instruction & 0xf800d000) == 0xf000d000) { 
        

        PUSHORT pDstInst = (PUSHORT)(pDest);
        BOOL fLink;
        LONG oldDelta = DecodeBranch24(instruction, fLink);
        PBYTE pTarget = CalculateTarget(pSource, oldDelta);
        m_pbTarget = pTarget;

        *--((PULONG&)m_pbPool) = (ULONG)(size_t)DETOURS_PBYTE_TO_PFUNC(pTarget);

        
        EmitLiteralLoad12(pDstInst, c_LR, m_pbPool);
        
        EmitShortInstruction(pDstInst, 0x47f0);

        
        m_lExtra = CalculateExtra(sizeof(DWORD), pDest, (BYTE*)(pDstInst));
        return sizeof(DWORD); 
    }

    if ((instruction & 0xFFF0FFFF) == 0xF3C08F00) {
        
        
        ASSERT(false);
    }

    if ((instruction & 0xFFFFFF00) == 0xF3DE8F00) {
        
        m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }

    
    return PureCopy32(pSource, pDest);
}

BYTE CDetourDis::CopyLiteralLoad32(BYTE* pSource, BYTE* pDest)
{
    BYTE* pStart = pDest;
    ULONG instruction = GetLongInstruction(pSource);

    LONG oldDelta = DecodeLiteralLoad12(instruction);
    PBYTE pTarget = CalculateTarget(Align4(pSource), oldDelta);

    LiteralLoad12& load = (LiteralLoad12&)(instruction);

    EmitLongLiteralLoad((PUSHORT&)pDest, load.Register, pTarget);

    m_lExtra = (LONG)(pDest - pStart - sizeof(DWORD));

    return sizeof(DWORD); 
}

BYTE CDetourDis::CopyLoadAndStoreSingle(BYTE* pSource, BYTE* pDest)
{
    ULONG instruction = GetLongInstruction(pSource);

    
    
    
    if (!(instruction & 0x100000)) {
        
        return PureCopy32(pSource, pDest);
    }

    if ((instruction & 0xF81F0000) == 0xF81F0000) {
        
        return CopyLiteralLoad32(pSource, pDest);
    }

    if ((instruction & 0xFE70F000) == 0xF81FF000) {
        
        
        if ((instruction & 0xFE7FF000) == 0xF81FF000) {
            PUSHORT pDstInst = (PUSHORT)(pDest);
            *pDstInst++ = c_NOP;
            *pDstInst++ = c_NOP;
            return sizeof(DWORD);  
        }

        
        return PureCopy32(pSource, pDest);
    }

    
    if ((instruction & 0xF950F000) == 0xF850F000) {
        m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }

    
    return PureCopy32(pSource, pDest);
}

BYTE CDetourDis::CopyLoadAndStoreMultipleAndSRS(BYTE* pSource, BYTE* pDest)
{
    
    return PureCopy32(pSource, pDest);
}

BYTE CDetourDis::CopyTableBranch(BYTE* pSource, BYTE* pDest)
{
    m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    ULONG instruction = GetLongInstruction(pSource);
    TableBranch& tableBranch = (TableBranch&)(instruction);

    
    if (tableBranch.BaseRegister != c_PC) {
        return PureCopy32(pSource, pDest);
    }

    __debugbreak();

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    PUSHORT pDstInst = (PUSHORT)(pDest);
    *pDstInst++ = 0xb401;

    
    BYTE scrReg = 0;
    while (scrReg == tableBranch.IndexRegister) {
        ++scrReg;
    }

    
    DWORD pushInstruction = 0xe92d0000;
    pushInstruction |= 1 << scrReg;
    pushInstruction |= 1 << tableBranch.IndexRegister;
    EmitLongInstruction(pDstInst, pushInstruction);

    
    
    
    BYTE* pTarget = CalculateTarget(pSource, 0);
    *--((PUSHORT&)m_pbPool) = (USHORT)((size_t)pTarget & 0xffff);
    *--((PUSHORT&)m_pbPool) = (USHORT)((size_t)pTarget >> 16);

    
    
    EmitLiteralLoad8(pDstInst, scrReg, m_pbPool);

    
    
    
    EmitAdd32(pDstInst, scrReg, tableBranch.IndexRegister, scrReg, tableBranch.HalfWord);

    
    
    if (scrReg < 0x7) {
        EmitImmediateRegisterLoad16(pDstInst, scrReg);
    }
    else {
        EmitImmediateRegisterLoad32(pDstInst, scrReg);
    }

    
    EmitLogicalShiftLeft32(pDstInst, scrReg, scrReg, 1);

    
    EmitAdd32(pDstInst, scrReg, c_PC, scrReg, 0);

    
    
    EmitStoreImmediate12(pDstInst, scrReg, c_SP, sizeof(DWORD) * 3);

    
    DWORD popInstruction = 0xe8bd0000;
    popInstruction |= 1 << scrReg;
    popInstruction |= 1 << tableBranch.IndexRegister;
    EmitLongInstruction(pDstInst, popInstruction);

    
    *pDstInst++ = 0xbd00;

    
    m_lExtra = CalculateExtra(sizeof(USHORT), pDest, (BYTE*)(pDstInst));
    return sizeof(DWORD);
}

BYTE CDetourDis::BeginCopy32(BYTE* pSource, BYTE* pDest)
{
    ULONG instruction = GetLongInstruction(pSource);

    
    if ((instruction & 0xF8008000) == 0xF0000000) { 
        
        
        
        return PureCopy32(pSource, pDest);
    }

    
    if ((instruction & 0xEE000000) == 0xEA000000) { 
        
        return PureCopy32(pSource, pDest);
    }

    
    if ((instruction & 0xFE000000) == 0xF8000000) { 
        return CopyLoadAndStoreSingle(pSource, pDest);
    }

    
    if ((instruction & 0xFE400000) == 0xE8400000) { 
        
        if (instruction & 0x1200000) {
            
            
            if ((instruction & 0xF0000) == 0xF0000) {
                
                ASSERT(false);
            }

            
            if (((instruction & 0xF000) == 0xF000) ||
                ((instruction & 0xF00) == 0xF00)) {
                m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
            }

            return PureCopy32(pSource, pDest);
        }

        
        if (!(instruction & 0x800000)) { 
            if ((instruction & 0xF000) == 0xF000) { 
                m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
            }
            return PureCopy32(pSource, pDest);
        }

        
        if ((instruction & 0x1000F0) == 0x100000 ||  
            (instruction & 0x1000F0) == 0x100010) { 
            return CopyTableBranch(pSource, pDest);
        }

        
        return PureCopy32(pSource, pDest);
    }

    
    if ((instruction & 0xFE400000) == 0xE8000000) { 
        
        if ((instruction & 0xE9900000) == 0xE9900000 || 
            (instruction & 0xE8100000) == 0xE8100000) { 
            return PureCopy32(pSource, pDest);
        }

        return CopyLoadAndStoreMultipleAndSRS(pSource, pDest);
    }

    
    if ((instruction & 0xF8008000) == 0xF0008000) { 
        
        return CopyBranchOrMiscellaneous32(pSource, pDest);
    }

    
    if ((instruction & 0xEC000000) == 0xEC000000) { 
        return PureCopy32(pSource, pDest);
    }

    
    ASSERT(false);
    return PureCopy32(pSource, pDest);
}



CDetourDis::CDetourDis()
{
    m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_NONE;
    m_pbPool = NULL;
    m_lExtra = 0;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pDst,
                                  PBYTE *ppDstPool,
                                  PBYTE pSrc,
                                  PBYTE *ppTarget,
                                  LONG *plExtra)
{
    if (pDst && ppDstPool && ppDstPool != NULL) {
        m_pbPool = (PBYTE)*ppDstPool;
    }
    else {
        pDst = m_rbScratchDst;
        m_pbPool = m_rbScratchDst + sizeof(m_rbScratchDst);
    }
    
    m_pbPool -= ((ULONG_PTR)m_pbPool) & 3;

    REFCOPYENTRY pEntry = &s_rceCopyTable[pSrc[1] >> 3];
    ULONG size = (this->*pEntry->pfCopy)(pSrc, pDst);

    pSrc += size;

    
    if (ppTarget) {
        *ppTarget = m_pbTarget;
    }
    if (plExtra) {
        *plExtra = m_lExtra;
    }
    if (ppDstPool) {
        *ppDstPool = m_pbPool;
    }

    return pSrc;
}


PVOID WINAPI DetourCopyInstruction(_In_opt_ PVOID pDst,
                                   _Inout_opt_ PVOID *ppDstPool,
                                   _In_ PVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget,
                                   _Out_opt_ LONG *plExtra)
{
    CDetourDis state;
    return (PVOID)state.CopyInstruction((PBYTE)pDst,
                                        (PBYTE*)ppDstPool,
                                        (PBYTE)pSrc,
                                        (PBYTE*)ppTarget,
                                        plExtra);
}

#endif 

#ifdef DETOURS_ARM64

#define c_LR        30          
#define c_SP        31          
#define c_NOP       0xd503201f  
#define c_BREAK     (0xd4200000 | (0xf000 << 5)) 




























class CDetourDis
{
  public:
    CDetourDis();

    PBYTE   CopyInstruction(PBYTE pDst,
                            PBYTE pSrc,
                            PBYTE *ppTarget,
                            LONG *plExtra);

  public:
    typedef BYTE (CDetourDis::* COPYFUNC)(PBYTE pbDst, PBYTE pbSrc);

    union AddImm12
    {
        DWORD Assembled;
        struct
        {
            DWORD Rd : 5;           
            DWORD Rn : 5;           
            DWORD Imm12 : 12;       
            DWORD Shift : 2;        
            DWORD Opcode1 : 7;      
            DWORD Size : 1;         
        } s;
        static DWORD Assemble(DWORD size, DWORD rd, DWORD rn, ULONG imm, DWORD shift)
        {
            AddImm12 temp;
            temp.s.Rd = rd;
            temp.s.Rn = rn;
            temp.s.Imm12 = imm & 0xfff;
            temp.s.Shift = shift;
            temp.s.Opcode1 = 0x11;
            temp.s.Size = size;
            return temp.Assembled;
        }
        static DWORD AssembleAdd32(DWORD rd, DWORD rn, ULONG imm, DWORD shift) { return Assemble(0, rd, rn, imm, shift); }
        static DWORD AssembleAdd64(DWORD rd, DWORD rn, ULONG imm, DWORD shift) { return Assemble(1, rd, rn, imm, shift); }
    };

    union Adr19
    {
        DWORD Assembled;
        struct
        {
            DWORD Rd : 5;           
            DWORD Imm19 : 19;       
            DWORD Opcode1 : 5;      
            DWORD Imm2 : 2;         
            DWORD Type : 1;         
        } s;
        inline LONG Imm() const { DWORD Imm = (s.Imm19 << 2) | s.Imm2; return (LONG)(Imm << 11) >> 11; }
        static DWORD Assemble(DWORD type, DWORD rd, LONG delta)
        {
            Adr19 temp;
            temp.s.Rd = rd;
            temp.s.Imm19 = (delta >> 2) & 0x7ffff;
            temp.s.Opcode1 = 0x10;
            temp.s.Imm2 = delta & 3;
            temp.s.Type = type;
            return temp.Assembled;
        }
        static DWORD AssembleAdr(DWORD rd, LONG delta) { return Assemble(0, rd, delta); }
        static DWORD AssembleAdrp(DWORD rd, LONG delta) { return Assemble(1, rd, delta); }
    };

    union Bcc19
    {
        DWORD Assembled;
        struct
        {
            DWORD Condition : 4;    
            DWORD Opcode1 : 1;      
            DWORD Imm19 : 19;       
            DWORD Opcode2 : 8;      
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm19 << 13) >> 11; }
        static DWORD AssembleBcc(DWORD condition, LONG delta)
        {
            Bcc19 temp;
            temp.s.Condition = condition;
            temp.s.Opcode1 = 0;
            temp.s.Imm19 = delta >> 2;
            temp.s.Opcode2 = 0x54;
            return temp.Assembled;
        }
    };

    union Branch26
    {
        DWORD Assembled;
        struct
        {
            DWORD Imm26 : 26;       
            DWORD Opcode1 : 5;      
            DWORD Link : 1;         
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm26 << 6) >> 4; }
        static DWORD Assemble(DWORD link, LONG delta)
        {
            Branch26 temp;
            temp.s.Imm26 = delta >> 2;
            temp.s.Opcode1 = 0x5;
            temp.s.Link = link;
            return temp.Assembled;
        }
        static DWORD AssembleB(LONG delta) { return Assemble(0, delta); }
        static DWORD AssembleBl(LONG delta) { return Assemble(1, delta); }
    };

    union Br
    {
        DWORD Assembled;
        struct
        {
            DWORD Opcode1 : 5;      
            DWORD Rn : 5;           
            DWORD Opcode2 : 22;     
        } s;
        static DWORD AssembleBr(DWORD rn)
        {
            Br temp;
            temp.s.Opcode1 = 0;
            temp.s.Rn = rn;
            temp.s.Opcode2 = 0x3587c0;
            return temp.Assembled;
        }
    };

    union Cbz19
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           
            DWORD Imm19 : 19;       
            DWORD Nz : 1;           
            DWORD Opcode1 : 6;      
            DWORD Size : 1;         
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm19 << 13) >> 11; }
        static DWORD Assemble(DWORD size, DWORD nz, DWORD rt, LONG delta)
        {
            Cbz19 temp;
            temp.s.Rt = rt;
            temp.s.Imm19 = delta >> 2;
            temp.s.Nz = nz;
            temp.s.Opcode1 = 0x1a;
            temp.s.Size = size;
            return temp.Assembled;
        }
    };

    union LdrLit19
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           
            DWORD Imm19 : 19;       
            DWORD Opcode1 : 2;      
            DWORD FpNeon : 1;       
            DWORD Opcode2 : 3;      
            DWORD Size : 2;         
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm19 << 13) >> 11; }
        static DWORD Assemble(DWORD size, DWORD fpneon, DWORD rt, LONG delta)
        {
            LdrLit19 temp;
            temp.s.Rt = rt;
            temp.s.Imm19 = delta >> 2;
            temp.s.Opcode1 = 0;
            temp.s.FpNeon = fpneon;
            temp.s.Opcode2 = 3;
            temp.s.Size = size;
            return temp.Assembled;
        }
    };

    union LdrFpNeonImm9
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           
            DWORD Rn : 5;           
            DWORD Imm12 : 12;       
            DWORD Opcode1 : 1;      
            DWORD Opc : 1;          
            DWORD Opcode2 : 6;      
            DWORD Size : 2;         
        } s;
        static DWORD Assemble(DWORD size, DWORD rt, DWORD rn, ULONG imm)
        {
            LdrFpNeonImm9 temp;
            temp.s.Rt = rt;
            temp.s.Rn = rn;
            temp.s.Imm12 = imm;
            temp.s.Opcode1 = 1;
            temp.s.Opc = size >> 2;
            temp.s.Opcode2 = 0x3d;
            temp.s.Size = size & 3;
            return temp.Assembled;
        }
    };

    union Mov16
    {
        DWORD Assembled;
        struct
        {
            DWORD Rd : 5;           
            DWORD Imm16 : 16;       
            DWORD Shift : 2;        
            DWORD Opcode : 6;       
            DWORD Type : 2;         
            DWORD Size : 1;         
        } s;
        static DWORD Assemble(DWORD size, DWORD type, DWORD rd, DWORD imm, DWORD shift)
        {
            Mov16 temp;
            temp.s.Rd = rd;
            temp.s.Imm16 = imm;
            temp.s.Shift = shift;
            temp.s.Opcode = 0x25;
            temp.s.Type = type;
            temp.s.Size = size;
            return temp.Assembled;
        }
        static DWORD AssembleMovn32(DWORD rd, DWORD imm, DWORD shift) { return Assemble(0, 0, rd, imm, shift); }
        static DWORD AssembleMovn64(DWORD rd, DWORD imm, DWORD shift) { return Assemble(1, 0, rd, imm, shift); }
        static DWORD AssembleMovz32(DWORD rd, DWORD imm, DWORD shift) { return Assemble(0, 2, rd, imm, shift); }
        static DWORD AssembleMovz64(DWORD rd, DWORD imm, DWORD shift) { return Assemble(1, 2, rd, imm, shift); }
        static DWORD AssembleMovk32(DWORD rd, DWORD imm, DWORD shift) { return Assemble(0, 3, rd, imm, shift); }
        static DWORD AssembleMovk64(DWORD rd, DWORD imm, DWORD shift) { return Assemble(1, 3, rd, imm, shift); }
    };

    union Tbz14
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           
            DWORD Imm14 : 14;       
            DWORD Bit : 5;          
            DWORD Nz : 1;           
            DWORD Opcode1 : 6;      
            DWORD Size : 1;         
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm14 << 18) >> 16; }
        static DWORD Assemble(DWORD size, DWORD nz, DWORD rt, DWORD bit, LONG delta)
        {
            Tbz14 temp;
            temp.s.Rt = rt;
            temp.s.Imm14 = delta >> 2;
            temp.s.Bit = bit;
            temp.s.Nz = nz;
            temp.s.Opcode1 = 0x1b;
            temp.s.Size = size;
            return temp.Assembled;
        }
    };


  protected:
    BYTE    PureCopy32(BYTE* pSource, BYTE* pDest);
    BYTE    EmitMovImmediate(PULONG& pDstInst, BYTE rd, UINT64 immediate);
    BYTE    CopyAdr(BYTE* pSource, BYTE* pDest, ULONG instruction);
    BYTE    CopyBcc(BYTE* pSource, BYTE* pDest, ULONG instruction);
    BYTE    CopyB(BYTE* pSource, BYTE* pDest, ULONG instruction);
    BYTE    CopyCbz(BYTE* pSource, BYTE* pDest, ULONG instruction);
    BYTE    CopyTbz(BYTE* pSource, BYTE* pDest, ULONG instruction);
    BYTE    CopyLdrLiteral(BYTE* pSource, BYTE* pDest, ULONG instruction);

  protected:
    ULONG GetInstruction(BYTE* pSource)
    {
        return ((PULONG)pSource)[0];
    }

    BYTE EmitInstruction(PULONG& pDstInst, ULONG instruction)
    {
        *pDstInst++ = instruction;
        return sizeof(ULONG);
    }

  protected:
    PBYTE   m_pbTarget;
    BYTE    m_rbScratchDst[64];
};

BYTE CDetourDis::PureCopy32(BYTE* pSource, BYTE* pDest)
{
    *(ULONG *)pDest = *(ULONG*)pSource;
    return sizeof(DWORD);
}



CDetourDis::CDetourDis()
{
    m_pbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_NONE;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pDst,
                                  PBYTE pSrc,
                                  PBYTE *ppTarget,
                                  LONG *plExtra)
{
    if (pDst == NULL) {
        pDst = m_rbScratchDst;
    }

    DWORD Instruction = GetInstruction(pSrc);

    ULONG CopiedSize;
    if ((Instruction & 0x1f000000) == 0x10000000) {
        CopiedSize = CopyAdr(pSrc, pDst, Instruction);
    } else if ((Instruction & 0xff000010) == 0x54000000) {
        CopiedSize = CopyBcc(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7c000000) == 0x14000000) {
        CopiedSize = CopyB(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7e000000) == 0x34000000) {
        CopiedSize = CopyCbz(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7e000000) == 0x36000000) {
        CopiedSize = CopyTbz(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x3b000000) == 0x18000000) {
        CopiedSize = CopyLdrLiteral(pSrc, pDst, Instruction);
    } else {
        CopiedSize = PureCopy32(pSrc, pDst);
    }

    
    if (ppTarget) {
        *ppTarget = m_pbTarget;
    }
    if (plExtra) {
        *plExtra = CopiedSize - sizeof(DWORD);
    }

    return pSrc + 4;
}

BYTE CDetourDis::EmitMovImmediate(PULONG& pDstInst, BYTE rd, UINT64 immediate)
{
    DWORD piece[4];
    piece[3] = (DWORD)((immediate >> 48) & 0xffff);
    piece[2] = (DWORD)((immediate >> 32) & 0xffff);
    piece[1] = (DWORD)((immediate >> 16) & 0xffff);
    piece[0] = (DWORD)((immediate >> 0) & 0xffff);
    int count = 0;

    
    if (piece[3] == 0 && piece[2] == 0 && piece[1] == 0xffff)
    {
        EmitInstruction(pDstInst, Mov16::AssembleMovn32(rd, piece[0] ^ 0xffff, 0));
        count++;
    }

    
    else
    {
        int zero_pieces = (piece[3] == 0x0000) + (piece[2] == 0x0000) + (piece[1] == 0x0000) + (piece[0] == 0x0000);
        int ffff_pieces = (piece[3] == 0xffff) + (piece[2] == 0xffff) + (piece[1] == 0xffff) + (piece[0] == 0xffff);
        DWORD defaultPiece = (ffff_pieces > zero_pieces) ? 0xffff : 0x0000;
        bool first = true;
        for (int pieceNum = 3; pieceNum >= 0; pieceNum--)
        {
            DWORD curPiece = piece[pieceNum];
            if (curPiece != defaultPiece || (pieceNum == 0 && first))
            {
                count++;
                if (first)
                {
                    if (defaultPiece == 0xffff)
                    {
                        EmitInstruction(pDstInst, Mov16::AssembleMovn64(rd, curPiece ^ 0xffff, pieceNum));
                    }
                    else
                    {
                        EmitInstruction(pDstInst, Mov16::AssembleMovz64(rd, curPiece, pieceNum));
                    }
                    first = false;
                }
                else
                {
                    EmitInstruction(pDstInst, Mov16::AssembleMovk64(rd, curPiece, pieceNum));
                }
            }
        }
    }
    return (BYTE)(count * sizeof(DWORD));
}

BYTE CDetourDis::CopyAdr(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Adr19& decoded = (Adr19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    
    if (decoded.s.Type == 0)
    {
        BYTE* pTarget = pSource + decoded.Imm();
        LONG64 delta = pTarget - pDest;
        LONG64 deltaPage = ((ULONG_PTR)pTarget >> 12) - ((ULONG_PTR)pDest >> 12);

        
        if (delta >= -(1 << 20) && delta < (1 << 20))
        {
            EmitInstruction(pDstInst, Adr19::AssembleAdr(decoded.s.Rd, (LONG)delta));
        }

        
        else if (deltaPage >= -(1 << 20) && (deltaPage < (1 << 20)))
        {
            EmitInstruction(pDstInst, Adr19::AssembleAdrp(decoded.s.Rd, (LONG)deltaPage));
            EmitInstruction(pDstInst, AddImm12::AssembleAdd32(decoded.s.Rd, decoded.s.Rd, ((ULONG)(ULONG_PTR)pTarget) & 0xfff, 0));
        }

        
        else
        {
            EmitMovImmediate(pDstInst, decoded.s.Rd, (ULONG_PTR)pTarget);
        }
    }

    
    else
    {
        BYTE* pTarget = (BYTE*)((((ULONG_PTR)pSource >> 12) + decoded.Imm()) << 12);
        LONG64 deltaPage = ((ULONG_PTR)pTarget >> 12) - ((ULONG_PTR)pDest >> 12);

        
        if (deltaPage >= -(1 << 20) && (deltaPage < (1 << 20)))
        {
            EmitInstruction(pDstInst, Adr19::AssembleAdrp(decoded.s.Rd, (LONG)deltaPage));
        }

        
        else
        {
            EmitMovImmediate(pDstInst, decoded.s.Rd, (ULONG_PTR)pTarget);
        }
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyBcc(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Bcc19& decoded = (Bcc19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    m_pbTarget = pTarget;
    LONG64 delta = pTarget - pDest;
    LONG64 delta4 = pTarget - (pDest + 4);

    
    if (delta >= -(1 << 20) && delta < (1 << 20))
    {
        EmitInstruction(pDstInst, Bcc19::AssembleBcc(decoded.s.Condition, (LONG)delta));
    }

    
    else if (delta4 >= -(1 << 27) && (delta4 < (1 << 27)))
    {
        EmitInstruction(pDstInst, Bcc19::AssembleBcc(decoded.s.Condition ^ 1, 8));
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta4));
    }

    
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Bcc19::AssembleBcc(decoded.s.Condition ^ 1, 8));
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyB(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Branch26& decoded = (Branch26&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    m_pbTarget = pTarget;
    LONG64 delta = pTarget - pDest;

    
    if (delta >= -(1 << 27) && (delta < (1 << 27)))
    {
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta));
    }

    
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyCbz(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Cbz19& decoded = (Cbz19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    m_pbTarget = pTarget;
    LONG64 delta = pTarget - pDest;
    LONG64 delta4 = pTarget - (pDest + 4);

    
    if (delta >= -(1 << 20) && delta < (1 << 20))
    {
        EmitInstruction(pDstInst, Cbz19::Assemble(decoded.s.Size, decoded.s.Nz, decoded.s.Rt, (LONG)delta));
    }

    
    else if (delta4 >= -(1 << 27) && (delta4 < (1 << 27)))
    {
        EmitInstruction(pDstInst, Cbz19::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, 8));
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta4));
    }

    
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Cbz19::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, 8));
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyTbz(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Tbz14& decoded = (Tbz14&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    m_pbTarget = pTarget;
    LONG64 delta = pTarget - pDest;
    LONG64 delta4 = pTarget - (pDest + 4);

    
    if (delta >= -(1 << 13) && delta < (1 << 13))
    {
        EmitInstruction(pDstInst, Tbz14::Assemble(decoded.s.Size, decoded.s.Nz, decoded.s.Rt, decoded.s.Bit, (LONG)delta));
    }

    
    else if (delta4 >= -(1 << 27) && (delta4 < (1 << 27)))
    {
        EmitInstruction(pDstInst, Tbz14::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, decoded.s.Bit, 8));
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta4));
    }

    
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Tbz14::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, decoded.s.Bit, 8));
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyLdrLiteral(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    LdrLit19& decoded = (LdrLit19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;

    
    if (delta >= -(1 << 21) && delta < (1 << 21))
    {
        EmitInstruction(pDstInst, LdrLit19::Assemble(decoded.s.Size, decoded.s.FpNeon, decoded.s.Rt, (LONG)delta));
    }

    
    else if (decoded.s.FpNeon == 0)
    {
        UINT64 value = 0;
        switch (decoded.s.Size)
        {
            case 0: value = *(ULONG*)pTarget;       break;
            case 1: value = *(UINT64*)pTarget;   break;
            case 2: value = *(LONG*)pTarget;        break;
        }
        EmitMovImmediate(pDstInst, decoded.s.Rt, value);
    }

    
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, LdrFpNeonImm9::Assemble(2 + decoded.s.Size, decoded.s.Rt, 17, 0));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}


PVOID WINAPI DetourCopyInstruction(_In_opt_ PVOID pDst,
                                   _Inout_opt_ PVOID *ppDstPool,
                                   _In_ PVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget,
                                   _Out_opt_ LONG *plExtra)
{
    UNREFERENCED_PARAMETER(ppDstPool);

    CDetourDis state;
    return (PVOID)state.CopyInstruction((PBYTE)pDst,
                                        (PBYTE)pSrc,
                                        (PBYTE*)ppTarget,
                                        plExtra);
}

#endif 

BOOL WINAPI DetourSetCodeModule(_In_ HMODULE hModule,
                                _In_ BOOL fLimitReferencesToModule)
{
#if defined(DETOURS_X64) || defined(DETOURS_X86)
    PBYTE pbBeg = NULL;
    PBYTE pbEnd = (PBYTE)~(ULONG_PTR)0;

    if (hModule != NULL) {
        ULONG cbModule = DetourGetModuleSize(hModule);

        pbBeg = (PBYTE)hModule;
        pbEnd = (PBYTE)hModule + cbModule;
    }

    return CDetourDis::SetCodeModule(pbBeg, pbEnd, fLimitReferencesToModule);
#elif defined(DETOURS_ARM) || defined(DETOURS_ARM64) || defined(DETOURS_IA64)
    (void)hModule;
    (void)fLimitReferencesToModule;
    return TRUE;
#else
#error unknown architecture (x86, x64, arm, arm64, ia64)
#endif
}



