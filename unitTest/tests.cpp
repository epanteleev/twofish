#include <random>
#include <ctime>
#include <vector>
#include <list>
#include <string>
#include <cstdlib>
#include "gtest/gtest.h"
#include "twofish.h"
#include <string>

using namespace twofish;
template<typename Twofish_mode>
class TwofishTestBase : public ::testing::Test {
protected:
    virtual void SetUp() {}
    virtual void setKey(const DWORD *keyMaterial_,const size_t keyLen_){
        key.addKey(keyMaterial_,keyLen_);
    }
    virtual void encrypt(const BYTE *input, size_t inputLen, BYTE *outBuffer){
        ecb.encrypt(key,input, inputLen, outBuffer);
    }
    virtual void decrypt(const BYTE *input, size_t inputLen, BYTE *outBuffer){
        ecb.decrypt(key,input, inputLen, outBuffer);
    }
    virtual void TearDown() {}
    Twofish_mode ecb;
    keyInstance key;
};

class TwofishTest_ECB : public TwofishTestBase<Twofish_ECB>{};
TEST_F(TwofishTest_ECB,test1){
    std::string str = "qweqqweqqweqqweq";
    const DWORD a[4] = {0x1,0x1,0x1,0x1};
    setKey(a,4);
    BYTE arr[60] = {0}, res[60] = {0};
    encrypt(reinterpret_cast<const BYTE*>(str.c_str()), str.length(), reinterpret_cast<BYTE*>(arr));
    decrypt(reinterpret_cast<const BYTE*>(arr), str.length(), reinterpret_cast<BYTE*>(res));
    ASSERT_EQ(str,reinterpret_cast<const char*>(res));
    ASSERT_NE(str,reinterpret_cast<const char*>(arr));
}

TEST_F(TwofishTest_ECB,test2){
    std::string str = "qwerqwerqwerqwerqwerqwerqwerqwer";
    const DWORD a[6] = {0x1,0x2,0x2,0xff,0xDF,0xFD};
    setKey(a,4);
    BYTE arr[60]{}, res[60]{};
    encrypt(reinterpret_cast<const BYTE*>(str.c_str()), str.length(), reinterpret_cast<BYTE*>(arr));
    decrypt(reinterpret_cast<const BYTE*>(arr), str.length(), reinterpret_cast<BYTE*>(res));
    ASSERT_EQ(str,reinterpret_cast<const char*>(res));
    ASSERT_NE(str,reinterpret_cast<const char*>(arr));
}

TEST_F(TwofishTest_ECB,test5){
    std::string str = "";
    const DWORD a[4] = {0x1,0x2,0x2,0xff};
    setKey(a,4);
    BYTE arr[60]{};
    ASSERT_THROW(encrypt(reinterpret_cast<const BYTE*>(str.c_str()), str.size(),
                         reinterpret_cast<unsigned char*>(arr)),bad_input_buffer);
}


class TwofishTest_CBC : public TwofishTestBase<Twofish_CBC>{
protected:
    void iv_set(BYTE* iv){
        ecb.addIv(iv,IV_SIZE);
    }
};

TEST_F(TwofishTest_CBC,test1){
    BYTE iv[16] = {0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4};
    std::string str = "qwerqwerqwerqwerqwerqwerqwerqwer";
    const DWORD a[6] = {0x1,0x2,0x2,0xff,0x2,0xff};

    setKey(a,6);
    iv_set(iv);
    BYTE arr[60]{}, res[60]{};
    encrypt(reinterpret_cast<const BYTE*>(str.c_str()), str.length(), reinterpret_cast<BYTE*>(arr));
    iv_set(iv);

    decrypt(reinterpret_cast<const BYTE*>(arr), str.length(), reinterpret_cast<BYTE*>(res));
    ASSERT_EQ(str,reinterpret_cast<const char*>(res));
    ASSERT_NE(str,reinterpret_cast<const char*>(arr));
}

TEST_F(TwofishTest_CBC,test2){
    BYTE iv[16] = {0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4};
    std::string str = "qwerqwerqwerqwer";
    const DWORD a[6] = {0x1,0x2,0x2,0xff,0x2,0xff};

    setKey(a,6);
    iv_set(iv);
    BYTE arr[60]{}, res[60]{};
    encrypt(reinterpret_cast<const BYTE*>(str.c_str()), str.length(), reinterpret_cast<BYTE*>(arr));
    iv_set(iv);

    decrypt(reinterpret_cast<const BYTE*>(arr), str.length(), reinterpret_cast<BYTE*>(res));
    ASSERT_EQ(str,reinterpret_cast<const char*>(res));
    ASSERT_NE(str,reinterpret_cast<const char*>(arr));
}

TEST_F(TwofishTest_CBC,test3){
    BYTE iv[16] = {0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4,0x1,0x2,0x3,0x4};
    std::string str = "qwerqwerqwerqwer";
    const DWORD a[6] = {0x1,0x2,0x2,0xff};

    setKey(a,4);
    iv_set(iv);
    BYTE arr[60] = {0}, res[60] = {0};
    encrypt(reinterpret_cast<const BYTE*>(str.c_str()), str.length(), reinterpret_cast<BYTE*>(arr));
    iv_set(iv);

    decrypt(reinterpret_cast<const BYTE*>(arr), str.length(), reinterpret_cast<BYTE*>(res));
    ASSERT_EQ(str,reinterpret_cast<const char*>(res));
    ASSERT_NE(str,reinterpret_cast<const char*>(arr));
}

int main(int argc, char *argv[]){
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
