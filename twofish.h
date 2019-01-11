#ifndef TWOFISH_H
#define TWOFISH_H
#include <iostream>
#include <vector>
#include <cstring>

#include "platform.h"
#include "table.h"
namespace twofish {

const int MAX_KEY_BITS = 256;	/* max number of bits of key */
const int MAX_KEY_SIZE = 64;	/* # of ASCII chars needed to represent a key */
const int MAX_ROUNDS = 16;	/* max # rounds (for allocating subkey array) */
const int BLOCK_SIZE = 128;	/* number of bits per block */
const int IV_SIZE = 16;
const int INPUT_WHITEN = 0;	/* subkey array indices */
const int OUTPUT_WHITEN = ( INPUT_WHITEN + BLOCK_SIZE/32);
const int ROUND_SUBKEYS = (OUTPUT_WHITEN + BLOCK_SIZE/32);	/* use 2 * (# rounds) */
const int TOTAL_SUBKEYS = (ROUND_SUBKEYS + 2*MAX_ROUNDS);
const int NUM_ROUNDS = 16; /* number of rounds */
const int MAX_IV_SIZE = 16;	/* # of bytes needed to represent an IV */
const DWORD	ADDR_XOR = 0;		/* convert byte address in dword */
const DWORD	RS_GF_FDBK = 0x14D;		/* field generator */
const  DWORD MDS_GF_FDBK = 0x169;	/* primitive polynomial for GF(256)*/

namespace internal {

DWORD f32(DWORD x,const DWORD *k32,size_t keyLen);
inline DWORD Bswap(DWORD x)noexcept{
    return x;
}
inline DWORD LFSR1(DWORD x)noexcept{
    return ((x >> 1) ^ ((x & 0x01) ? MDS_GF_FDBK / 2 : 0));
}
inline DWORD LFSR2(DWORD x)noexcept{
    return ((x >> 2) ^ ((x & 0x02) ? MDS_GF_FDBK / 2 : 0) ^ ((x & 0x01) ? MDS_GF_FDBK / 4 : 0));
}

inline DWORD  Mx_1(DWORD x) {
    return x;
}
inline DWORD	Mx_Y(DWORD x) {
    return  (x ^ LFSR1(x) ^ LFSR2(x));/* EF */
}
inline DWORD	Mx_X(DWORD x) {
    return (x ^ LFSR2(x));
}

inline DWORD	Mul_1(DWORD x) { return Mx_1(x); }
inline DWORD	Mul_X(DWORD x) { return Mx_X(x); }
inline DWORD	Mul_Y(DWORD x) { return Mx_Y(x); }

inline DWORD    M00(DWORD x) { return Mul_1(x); }
inline DWORD    M01(DWORD x) { return Mul_Y(x); }
inline DWORD    M02(DWORD x) { return Mul_X(x); }
inline DWORD	M03(DWORD x) { return Mul_X(x); }

inline DWORD	M10(DWORD x) { return Mul_X(x); }
inline DWORD	M11(DWORD x) { return Mul_Y(x); }
inline DWORD	M12(DWORD x) { return Mul_Y(x); }
inline DWORD	M13(DWORD x) { return Mul_1(x); }

inline DWORD	M20(DWORD x) { return Mul_Y(x); }
inline DWORD	M21(DWORD x) { return Mul_X(x); }
inline DWORD	M22(DWORD x) { return Mul_1(x); }
inline DWORD	M23(DWORD x) { return Mul_Y(x); }

inline DWORD	M30(DWORD x) { return Mul_Y(x); }
inline DWORD	M31(DWORD x) { return Mul_1(x); }
inline DWORD	M32(DWORD x) { return Mul_Y(x); }
inline DWORD	M33(DWORD x) { return Mul_X(x); }

inline BYTE	_b(DWORD x, int N) {
    return 	((BYTE *)(&x))[((N) & 3) ^ ADDR_XOR];/* pick bytes out of a dword */
}

inline BYTE b0(DWORD x) { return _b(x, 0); }
inline BYTE b1(DWORD x) { return _b(x, 1); }
inline BYTE b2(DWORD x) { return _b(x, 2); }
inline BYTE b3(DWORD x) { return _b(x, 3); }		/* extract MSB of DWORD */

}

class bad_key_material : public std::exception {
    char const* what() const noexcept {
        return "must have valid key";
    }
};

class bad_cipher_mode : public std::exception {
    const char* what() const noexcept{
        return "params struct passed to cipherInit invalid";
    }
};

class bad_key_mat : public std::exception {
    const char* what() const noexcept{
        return "key material not of correct length";
    }
};//BAD_KEY_INSTANCE
class bad_key_instance : public std::exception {
    const char* what() const noexcept{
        return "key passed is not valid";
    }
};//BAD_IV_MAT
class bad_iv_mat : public std::exception {
    const char* what() const noexcept{
        return "key material not of correct length";
    }
};//BAD_CIPHER_STATE
class bad_cipher_state : public std::exception {
    const char* what() const noexcept{
        return "cipher in wrong state (e.g., not initialized)";
    }
};//BAD_INPUT_LEN

class bad_input_len : public std::exception {
    const char* what() const noexcept{
        return "input length not a multiple of block size";
    }
};

class bad_input_buffer : public std::exception {
    const char* what() const noexcept{
        return "input buffer is not valid";
    }
};
class bad_output_buffer : public std::exception {
    const char* what() const noexcept{
        return "output buffer is not valid";
    }
};

class keyInstance{
private:
	static const DWORD SK_STEP = 0x02020202u;
	static const DWORD	SK_BUMP = 0x01010101u;
	static const DWORD	SK_ROTL = 9;
    static const int	MIN_KEY_BITS = 128;	/* min number of bits of key (zero pad) */


    static const int ROUNDS = 16;	/* default number of rounds for 128-bit keys*/
    static const int ROUNDS_192 = 16;	/* default number of rounds for 192-bit keys*/
    static const int ROUNDS_256 = 16;	/* default number of rounds for 256-bit keys*/
public:
    keyInstance() = default;
    keyInstance(const DWORD *keyMaterial_,const size_t keyLen_);
    inline size_t length()const noexcept {
		return keyLen;
    }
    void addKey(const DWORD *keyMaterial_,const size_t keyLen_);
    inline bool empty()const noexcept{
        return not keySig;
    }
    inline const DWORD* key()const noexcept{
        return key32;
    }
    inline const DWORD* subKey()const noexcept{
        return subKeys;
    }
    inline const DWORD* sboxKey()const noexcept{
        return sboxKeys;
    }
private:
    bool reKey();
    static DWORD RS_MDS_Encode(DWORD k0, DWORD k1);

	static inline void RS_rem(DWORD& x) {
		BYTE  b = (BYTE)(x >> 24);
        DWORD g2 = ((b << 1) ^ ((b & 0x80) ? RS_GF_FDBK : 0)) & 0xFF;
		DWORD g3 = ((b >> 1) & 0x7F) ^ ((b & 1) ? RS_GF_FDBK >> 1 : 0) ^ g2;
		x = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
	}
private:
    size_t  keyLen{};					/* Length of the key */
    /* Twofish-specific parameters: */
    bool keySig = false;					/* set to VALID_SIG by makeKey() */
    DWORD key32[MAX_KEY_BITS / 32]{};	/* actual key bits, in dwords */
    DWORD sboxKeys[MAX_KEY_BITS / 64]{};/* key bits used for S-boxes */
    DWORD subKeys[TOTAL_SUBKEYS]{};	/* round subkeys, input/output whitening bits */
};

int blockEncrypt(keyInstance& key,DWORD* x);

int blockDecrypt(keyInstance& key, DWORD* x);


class twofish{
public:
    twofish() = default;
    virtual ~twofish() = default;

public:
    virtual  void encrypt(keyInstance& key,const BYTE *input, size_t input_length, BYTE *outBuffer) = 0;
    virtual  void decrypt(keyInstance& key,const BYTE *input, size_t input_length, BYTE *outBuffer) = 0;
};

class Twofish_ECB final: public twofish{
public:
    void encrypt(keyInstance& key,const BYTE *input, size_t input_length, BYTE *outBuffer)override;
    void decrypt(keyInstance& key,const BYTE *input, size_t input_length, BYTE *outBuffer)override;
};

class Twofish_CBC final : public twofish{
public:
    void addIv(BYTE* Iv,size_t iv_length);
    void encrypt(keyInstance& key,const BYTE *input, size_t input_length, BYTE *outBuffer)override;
    void decrypt(keyInstance& key,const BYTE *input, size_t input_length, BYTE *outBuffer)override;
private:
    DWORD iv32[BLOCK_SIZE/32]{};
};

}
#endif
