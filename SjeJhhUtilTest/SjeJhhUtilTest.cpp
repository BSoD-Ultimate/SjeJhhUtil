﻿// SjeJhhUtilTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <cstring>
#include <memory>

#include "SjeJhhUtil.h"

const char testData[] = 
"[SYSTEM]\r\n"
"CLIENT_VERSION = 3000 ;odd(QA) even(REAL)\r\n"
"SERVER_TYPE = 1 ;0:QA 1:REAL\r\n"
"\r\n"
"[UI]\r\n"
"DEFAULT_FONT_NAME = DEFAULT\r\n"
"CHAT_FONT_COLOR = 255 255 255 255\r\n"
"FONT_CHAT_INDEX = 2\r\n"
"NOTICE_FONT_COLOR = 0 255 0 255\r\n"
"DEFAULT_CURSOR_FILE_NAME = UI\\cursor.dds\r\n"
"COLORKEY = 255 0 255 255\r\n\r\n";

int main(int argc, char** argv)
{
    // test encrypt & decrypt memory data
    int length = sjejhh_encrypt_stream(testData, strlen(testData), NULL, 0, "TOJ", 3);
    std::unique_ptr<char[]> encryptedData(new char[length]);
    sjejhh_encrypt_stream(testData, strlen(testData), encryptedData.get(), length, "TOJ", 3);

    int decryptLength = sjejhh_decrypt_stream(encryptedData.get(), length, NULL, 0, "TOJ", 3);
    std::unique_ptr<char[]> decryptedData(new char[decryptLength]);
    sjejhh_decrypt_stream(encryptedData.get(), length, decryptedData.get(), decryptLength, "TOJ", 3);

    // test encrypt & decrypt file using the key passed from arguments
    sjejhh_encrypt_file(L"config.ini", L"config_encrypted.ini", "TOJ", 3);
    sjejhh_decrypt_file(L"config_encrypted.ini", L"config_encrypted_decrypted.ini", "TOJ", 3);

    return 0;
}

