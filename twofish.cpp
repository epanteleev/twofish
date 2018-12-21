#include	"twofish.h"
#include	"table.h"

namespace twofish {

DWORD f32(DWORD x,const DWORD *k32,int keyLen){
    using namespace table;
	BYTE  b[4]{};
    /* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
    /* Note that each byte goes through a different combination of S-boxes.*/

	*(reinterpret_cast<DWORD *>(b)) = Bswap(x);	/* make b[0] = LSB, b[3] = MSB */
    switch (((keyLen + 63)/64) & 3){
        case 0:		/* 256 bits of key */
            b[0] = p8(04)[b[0]] ^ b0(k32[3]);
            b[1] = p8(14)[b[1]] ^ b1(k32[3]);
            b[2] = p8(24)[b[2]] ^ b2(k32[3]);
            b[3] = p8(34)[b[3]] ^ b3(k32[3]);
            /* fall thru, having pre-processed b[0]..b[3] with k32[3] */
        case 3:		/* 192 bits of key */
            b[0] = p8(03)[b[0]] ^ b0(k32[2]);
            b[1] = p8(13)[b[1]] ^ b1(k32[2]);
            b[2] = p8(23)[b[2]] ^ b2(k32[2]);
            b[3] = p8(33)[b[3]] ^ b3(k32[2]);
            /* fall thru, having pre-processed b[0]..b[3] with k32[2] */
        case 2:		/* 128 bits of key */
            b[0] = p8(00)[p8(01)[p8(02)[b[0]] ^ b0(k32[1])] ^ b0(k32[0])];
            b[1] = p8(10)[p8(11)[p8(12)[b[1]] ^ b1(k32[1])] ^ b1(k32[0])];
            b[2] = p8(20)[p8(21)[p8(22)[b[2]] ^ b2(k32[1])] ^ b2(k32[0])];
            b[3] = p8(30)[p8(31)[p8(32)[b[3]] ^ b3(k32[1])] ^ b3(k32[0])];
     }
    /* Now perform the MDS matrix multiply inline. */
    return	((M00(b[0]) ^ M01(b[1]) ^ M02(b[2]) ^ M03(b[3]))	  ) ^
            ((M10(b[0]) ^ M11(b[1]) ^ M12(b[2]) ^ M13(b[3])) <<  8) ^
            ((M20(b[0]) ^ M21(b[1]) ^ M22(b[2]) ^ M23(b[3])) << 16) ^
            ((M30(b[0]) ^ M31(b[1]) ^ M32(b[2]) ^ M33(b[3])) << 24) ;
}

int blockEncrypt(keyInstance& key, DWORD* x){
    DWORD t0,t1, tmp;
    for (int r = 0;r < NUM_ROUNDS;r++){			/* main Twofish encryption loop */
        t0	= f32(    x[0]   ,key.sboxKey(),key.length());
        t1	= f32(ROL(x[1],8),key.sboxKey(),key.length());

        x[3] = ROL(x[3],1);
        x[2]^= t0 +   t1 + key.subKey()[ROUND_SUBKEYS+2*r  ]; /* PHT, round keys */
        x[3]^= t0 + 2*t1 + key.subKey()[ROUND_SUBKEYS+2*r+1];
        x[2] = ROR(x[2],1);

        if (r < NUM_ROUNDS-1){	/* swap for next round */
            tmp = x[0]; x[0]= x[2]; x[2] = tmp;
            tmp = x[1]; x[1]= x[3]; x[3] = tmp;
        }
    }
    return 0;
}


int blockDecrypt(keyInstance& key,DWORD* x){
    DWORD t0,t1;
    for (int r = NUM_ROUNDS-1;r >= 0;r--){			/* main Twofish decryption loop */
        t0 = f32(x[0],key.sboxKey(),key.length());
        t1 = f32(ROL(x[1],8),key.sboxKey(),key.length());

        x[2] = ROL(x[2],1);
        x[2]^= t0 + t1 + key.subKey()[ROUND_SUBKEYS+2*r  ]; /* PHT, round keys */
        x[3]^= t0 + 2*t1 + key.subKey()[ROUND_SUBKEYS+2*r+1];
        x[3] = ROR(x[3],1);

        if (r){									/* unswap, except for last round */
            t0  = x[0]; x[0]= x[2]; x[2] = t0;
            t1  = x[1]; x[1]= x[3]; x[3] = t1;
        }
    }
    return 0;
}


int Twofish_ECB::encrypt(keyInstance& key,const BYTE *input, size_t inputLen, BYTE *outBuffer){
    if (key.empty()){
        throw bad_key_instance();
    }
    if(input == nullptr || inputLen <= 0){
        throw bad_input_buffer();
    }
    if(outBuffer == nullptr){
        throw bad_output_buffer();
    }
    DWORD x[BLOCK_SIZE / 32]{};			/* block being encrypted */
    for (size_t n = 0; n < inputLen;n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8){
        for (int i = 0;i<BLOCK_SIZE/32;i++)	/* copy in the block, add whitening */{
            x[i] = Bswap(reinterpret_cast<const DWORD *>(input)[i]) ^ key.subKey()[INPUT_WHITEN+i];
        }
        blockEncrypt(key,x);
        for (size_t i = 0;i<BLOCK_SIZE/32;i++)	/* copy out, with whitening */{
            reinterpret_cast<DWORD *>(outBuffer)[i] = Bswap(x[i] ^ key.subKey()[OUTPUT_WHITEN+i]);
        }
    }
    return inputLen;
}
int Twofish_ECB::decrypt(keyInstance& key,const BYTE *input, size_t inputLen, BYTE *outBuffer){
    if(input == nullptr || inputLen <= 0){
        throw bad_input_buffer();
    }
    DWORD x[BLOCK_SIZE/32]{};			/* block being encrypted */
    if (key.empty()){
        throw bad_key_instance();
    }
    if(input == nullptr || inputLen <= 0){
        throw bad_input_buffer();
    }
    if(outBuffer == nullptr){
        throw bad_output_buffer();
    }
    for (size_t n = 0;n<inputLen;n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8){
        for (size_t i=0;i<BLOCK_SIZE/32;i++){	/* copy in the block, add whitening */
            x[i] = Bswap(reinterpret_cast<const DWORD *>(input)[i]) ^ key.subKey()[OUTPUT_WHITEN+i];
        }
        blockDecrypt(key,x);
        for (size_t i = 0;i < BLOCK_SIZE/32 ;i++){	/* copy out, with whitening */
            x[i] ^= key.subKey()[INPUT_WHITEN + i];
            reinterpret_cast<DWORD *>(outBuffer)[i]  = Bswap(x[i]);
        }
    }
    return inputLen;
}

void Twofish_CBC::addIv(BYTE* Iv){
    if(Iv == nullptr){
        throw bad_input_buffer();
    }
    std::memcpy(iv32,Iv,BLOCK_SIZE/8);
}

int Twofish_CBC::encrypt(keyInstance& key,const BYTE *input, size_t inputLen, BYTE *outBuffer){
    if (key.empty()){
        throw bad_key_instance();
    }
    if(input == nullptr || inputLen <= 0){
        throw bad_input_buffer();
    }
    if(outBuffer == nullptr){
        throw bad_output_buffer();
    }
    DWORD x[BLOCK_SIZE / 32]{};			/* block being encrypted */
    for (size_t n = 0; n < inputLen;n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8){
        for (int i = 0;i<BLOCK_SIZE/32;i++)	/* copy in the block, add whitening */{
            x[i] = Bswap(reinterpret_cast<const DWORD *>(input)[i]) ^ key.subKey()[INPUT_WHITEN+i];
            x[i] ^= Bswap(iv32[i]);
        }
        blockEncrypt(key,x);
        for (size_t i = 0;i<BLOCK_SIZE/32;i++)	/* copy out, with whitening */{
            reinterpret_cast<DWORD *>(outBuffer)[i] = Bswap(x[i] ^ key.subKey()[OUTPUT_WHITEN+i]);
            iv32[i] = ((DWORD *)outBuffer)[i];
        }
    }
    return inputLen;
}

int Twofish_CBC::decrypt(keyInstance& key,const BYTE *input, size_t inputLen, BYTE *outBuffer){
    if(input == nullptr || inputLen <= 0){
        throw bad_input_buffer();
    }
    DWORD x[BLOCK_SIZE/32]{};			/* block being encrypted */
    if (key.empty()){
        throw bad_key_instance();
    }
    if(input == nullptr || inputLen <= 0){
        throw bad_input_buffer();
    }
    if(outBuffer == nullptr){
        throw bad_output_buffer();
    }
    for (size_t n = 0;n<inputLen;n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8){
        for (size_t i=0;i<BLOCK_SIZE/32;i++){	/* copy in the block, add whitening */
            x[i] = Bswap(reinterpret_cast<const DWORD *>(input)[i]) ^ key.subKey()[OUTPUT_WHITEN+i];
        }
        blockDecrypt(key,x);
        for (size_t i = 0;i < BLOCK_SIZE/32 ;i++){	/* copy out, with whitening */
            x[i] ^= key.subKey()[INPUT_WHITEN + i];
            x[i] ^= Bswap(iv32[i]);
            iv32[i] = ((DWORD *)input)[i];
            reinterpret_cast<DWORD *>(outBuffer)[i]  = Bswap(x[i]);
        }
    }
    return inputLen;
}

}
