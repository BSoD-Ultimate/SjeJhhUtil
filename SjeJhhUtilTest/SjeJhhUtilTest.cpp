// SjeJhhUtilTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "SjeJhhUtil.h"

int main(int argc, char** argv)
{
    sjejhh_encrypt_file(L"config.ini", L"config_encrypted.ini", "TOJ", 3);
    sjejhh_encrypt_file(L"config_encrypted.ini", L"config_encrypted_encrypted.ini", "TOJ", 3);
    return 0;
}

