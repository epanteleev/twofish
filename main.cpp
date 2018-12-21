#ifdef _WIN32
#define  _CRT_SECURE_NO_WARNINGS
#endif // _WIN32

#include <iostream>
#include <assert.h>
#include <cstring>

#include "twofish.h"

using namespace twofish;

static const char* directory = "/home/user/Sources/twofish/tests/";

int TestFileTwoFish(const char* type, int keySize){
    DWORD key32[8]{};
    char name[1024];
    long textSize;
    sprintf(name, "%s" "key%d.txt",directory, keySize);
    FILE* file = fopen(name, "rb");
    if (file == NULL)
        return 1;
    if (fread(key32, keySize / 8, 1, file) != 1) /* select key bits */{
        return 1;
    }
    fclose(file);
    keyInstance    ki;
    ki.addKey(key32,keySize);
    sprintf(name, "%s" "plain.txt",directory);
    file = fopen(name, "rb");
    if (file == NULL){
        return 1;
    }
    fseek(file, 0, SEEK_END);
    textSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *plain = (BYTE*)malloc(textSize);
    BYTE *reference = new BYTE[textSize];
    BYTE *encrypted = new BYTE[textSize];
    BYTE *decrypted = new BYTE[textSize];

    fread(plain, textSize, 1, file);
    fclose(file);

    /* encrypt the bytes */
    std::cerr<<"START ENCRYPT. FILE:   "<<name<<std::endl;
    Twofish_ECB ci;

    if (ci.encrypt(ki, plain, textSize * 8, encrypted) != textSize * 8){
        return 1;
    }
    sprintf(name, "%s""encrypt_%s_%d.txt", directory, type, keySize);
    std::cerr << "READ ENCRYPT. FILE:   " << name << std::endl;
    file = fopen(name, "rb");
    if (file == NULL){
        return 1;
    }
    fread(reference, textSize, 1, file);
    assert(not memcmp(reference, encrypted, textSize));
    delete[] reference;
    fclose(file);

    std::cerr<<"START DECRYPT. FILE:   "<<name<<std::endl;
    if (ci.decrypt(ki, encrypted, textSize * 8, decrypted) != textSize * 8){
        return 1;
    }

    free(encrypted);

    /* make sure the decrypt output matches original plaintext */
    assert(not memcmp(plain, decrypted, textSize));
    delete [] plain;
    delete [] decrypted;
    std::cerr<<"TEST PASSED"<<std::endl;
    return 0;					/* tests passed! */
}

int TestFileTwoFish_CBC(const char* type, int keySize){
    DWORD key32[8]{};
    char name[1024];
    long textSize;
    sprintf(name, "%s" "key%d.txt",directory, keySize);
    FILE* file = fopen(name, "rb");
    if (file == NULL)
        return 1;
    if (fread(key32, keySize / 8, 1, file) != 1) /* select key bits */{
        return 1;
    }
    fclose(file);
    keyInstance    ki;
    ki.addKey(key32,keySize);
    sprintf(name, "%s" "plain.txt",directory);
    file = fopen(name, "rb");
    if (file == NULL){
        return 1;
    }
    fseek(file, 0, SEEK_END);
    textSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *plain = (BYTE*)malloc(textSize);
    BYTE *reference = new BYTE[textSize];
    BYTE *encrypted = new BYTE[textSize];
    BYTE *decrypted = new BYTE[textSize];

    fread(plain, textSize, 1, file);
    fclose(file);

    /* encrypt the bytes */
    std::cerr<<"START ENCRYPT. FILE:   "<<name<<std::endl;
    Twofish_CBC ci;
    BYTE iv[BLOCK_SIZE / 8]{};
    sprintf(name, "%s""iv.txt", directory);
    file = fopen(name, "rb");
    if (file == NULL){
        return 1;
    }
    fread(iv, BLOCK_SIZE / 8, 1, file);	/* select key bits */
    fclose(file);
    ci.addIv(iv);

    if (ci.encrypt(ki, plain, textSize * 8, encrypted) != textSize * 8){
        return 1;
    }
    sprintf(name, "%s""encrypt_%s_%d.txt", directory, type, keySize);
    std::cerr << "READ ENCRYPT. FILE:   " << name << std::endl;
    file = fopen(name, "rb");
    if (file == NULL){
        return 1;
    }
    fread(reference, textSize, 1, file);
    assert(not memcmp(reference, encrypted, textSize));
    delete[] reference;
    fclose(file);

    std::cerr<<"START DECRYPT. FILE:   "<<name<<std::endl;
    ci.addIv(iv);
    if (ci.decrypt(ki, encrypted, textSize * 8, decrypted) != textSize * 8){
        return 1;
    }

    free(encrypted);

    /* make sure the decrypt output matches original plaintext */
    assert(not memcmp(plain, decrypted, textSize));
    delete [] plain;
    delete [] decrypted;
    std::cerr<<"TEST PASSED"<<std::endl;
    return 0;					/* tests passed! */
}

int main(){
    TestFileTwoFish_CBC("CBC", 128);
    TestFileTwoFish_CBC("CBC", 192);
    TestFileTwoFish_CBC("CBC", 256);
    TestFileTwoFish("ECB", 128);
    TestFileTwoFish("ECB", 192);
    TestFileTwoFish("ECB", 256);
    return 0;
}
