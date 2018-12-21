#include <random>
#include <ctime>
#include <vector>
#include <list>
#include <string>

#include "gtest/gtest.h"
#include "twofish.h"
#include <string>

using namespace twofish;
class TestCase : public ::testing::Test {
protected:
    virtual void SetUp() {}

    virtual void TearDown() {}
};

TEST(twofish_key_128_,test1){
    std::string str = "qweqqweqqweqqweq";
    std::string key_str = "qweqqweqqweqqweq";
    char arr[60] = {0}, res[60] = {0};
    cipherInstance cr;
    keyInstance key(key_str.size()*8,(char*)key_str.c_str());
    cr.blockEncrypt(key, (unsigned char*)str.c_str(), str.size()*8, (unsigned char*)arr);
    cr.blockDecrypt(key, (unsigned char*)arr, str.size()*8, (unsigned char*)res);
    ASSERT_EQ(str,res);
    ASSERT_NE(str,arr);
}
TEST(twofish_key_128_,test2){
    std::string str = "qweqqweqqweqqweq12321312312312312312312312321312312";
    std::string key_str = "qweqqweqqweqqweq";
    char arr[60] = {0}, res[60] = {0};
    cipherInstance cr;
    keyInstance key(key_str.size()*8,(char*)key_str.c_str());
    cr.blockEncrypt(key, (unsigned char*)str.c_str(), str.size()*8, (unsigned char*)arr);
    cr.blockDecrypt(key, (unsigned char*)arr, str.size()*8, (unsigned char*)res);
    ASSERT_EQ(str,res);
    ASSERT_NE(str,arr);
}
TEST(twofish_key_128_,test3){
    std::string str = "qweqqweqq";
    std::string key_str = "qweqqweqqweqqweq";
    char arr[60] = {0}, res[60] = {0};
    cipherInstance cr;
    keyInstance key(key_str.size()*8,(char*)key_str.c_str());
    cr.blockEncrypt(key, (unsigned char*)str.c_str(), str.size()*8, (unsigned char*)arr);
    cr.blockDecrypt(key, (unsigned char*)arr, str.size()*8, (unsigned char*)res);
    ASSERT_EQ(str,res);
    ASSERT_NE(str,arr);
}
TEST(twofish_key_128_,test4){
    std::string str = "qweqqweqq";
    std::string key_str = "qweqqweqqweqqweq";
    keyInstance key(key_str.size()*8,(char*)key_str.c_str());
    cipherInstance cr;
    char arr[60] = {0}, res[60] = {0};
    ASSERT_THROW(cr.blockEncrypt(key, (unsigned char*)str.c_str(), str.size()*8, nullptr),bad_input_buffer);
    ASSERT_THROW(cr.blockEncrypt(key, (unsigned char*)str.c_str(), -234, (unsigned char*)arr), bad_output_buffer);

}
TEST(twofish_key_192,test4){
    std::string str = "qweqqweqq";
    std::string key_str = "qweqqweqqweqqweqqwerqwer";
    char arr[60] = {0}, res[60] = {0};
    cipherInstance cr;
    keyInstance key(key_str.size()*8,(char*)key_str.c_str());
    cr.blockEncrypt(key, (unsigned char*)str.c_str(), str.size()*8, (unsigned char*)arr);
    cr.blockDecrypt(key, (unsigned char*)arr, str.size()*8, (unsigned char*)res);
    ASSERT_EQ(str,res);
    ASSERT_NE(str,arr);
}
int main(int argc, char *argv[]){
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
