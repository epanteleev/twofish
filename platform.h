#ifndef PLATFORM_H
#define PLATFORM_H
namespace twofish {

#ifdef  _WIN32 
#include <Windows.h>
#else
	using BYTE = unsigned char;
    using DWORD = unsigned int;
#endif

#ifdef _MSC_VER
#include	<cstdlib>					/* get prototypes for rotation functions */
#pragma intrinsic(_lrotl,_lrotr)		/* use intrinsic compiler rotations */
	inline DWORD ROR(DWORD x, DWORD n) noexcept {
		return _lrotr(x, n);
	}
	inline DWORD ROL(DWORD x, DWORD n)noexcept {
		return _lrotl(x, n);
	}
#elif __GNUC__
    inline DWORD ROR(DWORD x, BYTE r) {
          asm("rorl %1,%0" : "+r" (x) : "c" (r));
          return x;
    }
    inline DWORD ROL(DWORD x, BYTE r) {
          asm("roll %1,%0" : "+r" (x) : "c" (r));
          return x;
    }
#else
	inline DWORD ROR(DWORD x, DWORD n) noexcept {
        return ((x >> (n & 0x1F)) | (x << (32 - (n & 0x1F))));
	}
	inline DWORD ROL(DWORD x, DWORD n)noexcept {
		return ((x << (n & 0x1F)) | (x >> (32 - (n & 0x1F))));
	}
#endif
	static_assert(sizeof(DWORD) == 4, "DWORD isn't valid");
	static_assert(sizeof(BYTE) == 1, "BYTE isn't valid");
}

#endif
