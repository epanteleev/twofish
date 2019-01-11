#include "twofish.h"
#include <cstring>
using namespace twofish;

DWORD keyInstance::RS_MDS_Encode(DWORD k0,DWORD k1){
    DWORD r;
    for (DWORD i=r=0;i<2;i++){
        r ^= (i) ? k0 : k1;			/* merge in 32 more key bits */
        for (int j = 0; j < 4; j++) {			/* shift one byte at a time */
			RS_rem(r);
		}
    }
    return r;
}

bool keyInstance::reKey(){
    using namespace internal;
    int		k64Cnt;
    size_t 	subkeyCnt = ROUND_SUBKEYS + 2 * NUM_ROUNDS;
    DWORD	A,B;
    DWORD	k32e[MAX_KEY_BITS/64],k32o[MAX_KEY_BITS/64]; /* even/odd key dwords */
	if (subkeyCnt > TOTAL_SUBKEYS) {
        throw bad_key_instance();
	}

    k64Cnt=(keyLen+63)/64;		/* round up to next multiple of 64 bits */
    for (size_t i=0;i<k64Cnt;i++){						/* split into even/odd key dwords */
        k32e[i] = key32[2*i  ];
        k32o[i] = key32[2*i+1];
        /* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
        sboxKeys[k64Cnt-1-i] = RS_MDS_Encode(k32e[i],k32o[i]); /* reverse order */
    }

    for (size_t i=0;i<subkeyCnt/2;i++){				/* compute round subkeys for PHT */
        A = f32(i*SK_STEP      ,k32e,keyLen);	/* A uses even key dwords */
        B = f32(i*SK_STEP+SK_BUMP,k32o,keyLen);	/* B uses odd  key dwords */
        B = ROL(B,8);
        subKeys[2*i] = A + B;			/* combine with a PHT */
        subKeys[2*i+1] = ROL(A+2*B,SK_ROTL);
    }
    return true;
}

keyInstance::keyInstance(const DWORD *keyMaterial_,const size_t keyLen_){
    addKey(keyMaterial_,keyLen_);
}
void keyInstance::addKey(const DWORD *keyMaterial_,const size_t keyLen_){
    if (keyMaterial_ == nullptr) {
        throw bad_key_material();
    }
    keySig = true;
    keyLen = keyLen_*32;
    if ((keyLen > MAX_KEY_BITS) || (keyLen % 64) || (keyLen < MIN_KEY_BITS)) {
        throw bad_key_instance();
    }
    memcpy(reinterpret_cast<void*>(key32), reinterpret_cast<const void*>(keyMaterial_),keyLen);
    reKey();			/* generate round subkeys */
}
