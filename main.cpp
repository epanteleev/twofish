#ifdef _WIN32
#define  _CRT_SECURE_NO_WARNINGS
#endif // _WIN32

#include <iostream>
#include <assert.h>
#include <cstring>

#include "twofish.h"

using namespace twofish;

static const char* directory = "/home/user/Development/twofish/tests/";

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

    BYTE *plain = new BYTE[textSize];
    BYTE *reference = new BYTE[textSize];
    BYTE *encrypted = new BYTE[textSize];
    BYTE *decrypted = new BYTE[textSize];

    fread(plain, textSize, 1, file);
    fclose(file);

    /* encrypt the bytes */
    std::cerr<<"START ENCRYPT. FILE:   "<<name<<std::endl;
    Twofish_ECB ci;

    if (ci.encrypt(ki, plain, textSize, encrypted) != textSize){
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
    if (ci.decrypt(ki, encrypted, textSize, decrypted) != textSize){
        return 1;
    }

    free(encrypted);

    /* make sure the decrypt output matches original plaintext */
    assert(not memcmp(plain, decrypted, textSize));
    delete [] plain;
    delete [] decrypted;
    std::cerr<<"[...TEST PASSED...]"<<std::endl;
    return 0;					/* tests passed! */
}

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
template<typename TYPE>
int TestFileTwoFish_CBC(const char* type, int keySize){
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
    ki.addKey(key32,keySize);
    sprintf(name, "%s" "plain.txt",directory);
    size_t textSize = file_size(name);
    BYTE * plain = read_file(name,textSize);
    //BYTE *plain = (BYTE*)malloc(textSize);


    /* encrypt the bytes */
    std::cerr<<"START ENCRYPT. FILE:   "<<name<<std::endl;
    TYPE ci;
    BYTE iv[BLOCK_SIZE / 8]{};
    if(typeof (ci)){
        sprintf(name, "%s""iv.txt", directory);
        file = fopen(name, "rb");
        if (file == nullptr){
            return 1;
        }
        fread(iv, IV_SIZE, 1, file);	/* select key bits */
        fclose(file);
        ci.addIv(iv,IV_SIZE);
    }
    BYTE *encrypted = new BYTE[textSize];
    if (ci.encrypt(ki, plain, textSize, encrypted) != textSize){
        return 1;
    }
    sprintf(name, "%s""encrypt_%s_%d.txt", directory, type, keySize);
    std::cerr << "READ ENCRYPT. FILE:   " << name << std::endl;

    BYTE *reference = read_file(name,textSize);
    assert(not memcmp(reference, encrypted, textSize));
    delete[] reference;

    std::cerr<<"START DECRYPT. FILE:   "<<name<<std::endl;
    ci.addIv(iv,IV_SIZE);
    BYTE *decrypted = new BYTE[textSize];
    if (ci.decrypt(ki, encrypted, textSize, decrypted) != textSize ){
        return 1;
    }

    delete[] encrypted;
    assert(not memcmp(plain, decrypted, textSize));
    delete [] plain;
    delete [] decrypted;
    std::cerr<<"[...TEST PASSED...]"<<std::endl;
    return 0;					/* tests passed! */
}

int main(){
    if(TestFileTwoFish_CBC("CBC", 128)){

    }
    TestFileTwoFish_CBC("CBC", 192);
    TestFileTwoFish_CBC("CBC", 256);
    TestFileTwoFish("ECB", 128);
    TestFileTwoFish("ECB", 192);
    TestFileTwoFish("ECB", 256);
    return 0;
}
