#pragma once

#include <wincrypt.h>

namespace SjeJhhUtil
{
    class CCryptContext
    {
    public:
        CCryptContext();
        ~CCryptContext();

        CCryptContext(const CCryptContext&) = delete;
        CCryptContext& operator=(const CCryptContext&) = delete;

        HCRYPTPROV Get() const;
    private:
        HCRYPTPROV m_cryptContext;
    };

    class CCryptKey
    {
    public:
        CCryptKey(HCRYPTKEY cryptKey = NULL);
        ~CCryptKey();

        CCryptKey(const CCryptKey&) = delete;
        CCryptKey& operator=(const CCryptKey&) = delete;

        CCryptKey(CCryptKey&& other);
        CCryptKey& operator=(CCryptKey&& other);

        HCRYPTKEY get() const;

        void reset(HCRYPTKEY cryptKey = NULL);

        HCRYPTKEY release();

        HCRYPTKEY* operator&();

    private:
        HCRYPTKEY m_key;
    };



    class CCryptKeyHash
    {
    public:
        CCryptKeyHash(HCRYPTPROV hCryptContext, ALG_ID algorithmId, HCRYPTKEY key = NULL, DWORD flags = 0);
        ~CCryptKeyHash();

        CCryptKeyHash(const CCryptKeyHash&) = delete;
        CCryptKeyHash& operator=(const CCryptKeyHash&) = delete;

        HCRYPTHASH Get() const;
    private:
        HCRYPTHASH m_cryptHash;
    };
}



