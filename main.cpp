#ifdef _WIN32
#define  _CRT_SECURE_NO_WARNINGS
#endif // _WIN32

#include <iostream>
#include <assert.h>
#include <cstring>

#include "twofish.h"

using namespace twofish;

static const char* directory = "test/";

BYTE * read_file(const char* filename,size_t read_size){
    BYTE *plain = new BYTE[read_size];
    FILE* file = fopen(filename, "rb");
    if (file == nullptr){
        return nullptr;
    }
    fread(plain, read_size, 1, file);
    fclose(file);
    return plain;
}
size_t file_size(const char* filename){
    FILE* file = fopen(filename, "rb");
    if (file == nullptr){
        return 0;
    }
    fseek(file, 0, SEEK_END);
    size_t textSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    fclose(file);
    return textSize;
}
template<typename T>
typename std::enable_if<std::is_same<Twofish_ECB,T>::value, void>::type
    read_iv(const char* name, T& ci){
    return;
}

template<typename T>
typename std::enable_if<std::is_same<Twofish_CBC,T>::value, void>::type
    read_iv(const char* name, T& ci){
    BYTE iv[BLOCK_SIZE / 8]{};
    FILE* file = fopen(name, "rb");
    if (file == nullptr){
        return;
    }
    fread(iv, IV_SIZE, 1, file);	/* select key bits */
    fclose(file);
    ci.addIv(iv,IV_SIZE);
}

template<typename Type>
inline int TestFileTwoFish(const char* type, int keySize){
    DWORD key32[8]{};
    char name[1024];

    sprintf(name, "%s" "key%d.txt",directory, keySize);
    FILE* file = fopen(name, "rb");
    if (file == nullptr){
        return 1;
    }
    if (fread(key32, keySize / 8, 1, file) != 1) /* select key bits */{
        return 1;
    }
    fclose(file);
    keyInstance    ki;
    ki.addKey(key32,keySize/32);
    sprintf(name, "%s" "plain.txt",directory);
    size_t textSize = file_size(name);
    BYTE * plain = read_file(name,textSize);

    /* encrypt the bytes */
    std::cerr<<"START ENCRYPT. FILE:   "<<name<<std::endl;
    Type ci;

    sprintf(name, "%s""iv.txt", directory);
    read_iv(name,ci);

    BYTE *encrypted = new BYTE[textSize];
    ci.encrypt(ki, plain, textSize, encrypted);

    sprintf(name, "%s""encrypt_%s_%d.txt", directory, type, keySize);
    std::cerr << "READ ENCRYPT FILE"<<std::endl;

    BYTE *reference = read_file(name,textSize);
    assert(not memcmp(reference, encrypted, textSize));
    delete[] reference;

    std::cerr<<"START DECRYPT. FILE:   "<<name<<std::endl;
    sprintf(name, "%s""iv.txt", directory);
    read_iv(name, ci);

    BYTE *decrypted = new BYTE[textSize];
    ci.decrypt(ki, encrypted, textSize, decrypted);

    delete[] encrypted;
    assert(not memcmp(plain, decrypted, textSize));
    delete [] plain;
    delete [] decrypted;
    std::cerr<<"[...TEST PASSED...]"<<std::endl;
    return 0;					/* tests passed! */
}

int main(){
    TestFileTwoFish<Twofish_CBC>("CBC", 128);
    TestFileTwoFish<Twofish_CBC>("CBC", 192);
    TestFileTwoFish<Twofish_CBC>("CBC", 256);
    TestFileTwoFish<Twofish_ECB>("ECB", 128);
    TestFileTwoFish<Twofish_ECB>("ECB", 192);
    TestFileTwoFish<Twofish_ECB>("ECB", 256);
    return 0;
}
