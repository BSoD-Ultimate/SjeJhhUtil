#include "stdafx.h"
#include "CryptUtil.h"

namespace SjeJhhUtil
{
    CCryptContext::CCryptContext()
        : m_cryptContext(NULL)
    {
        if (!CryptAcquireContextW(&m_cryptContext, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0) &&  // try open existing
            !CryptAcquireContextW(&m_cryptContext, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)) // new context
        {
            int error = GetLastError();
            throw std::runtime_error(util::generate_errorMsg("An error has occurred during CryptAcquireContext!", error));
        }
    }
    CCryptContext::~CCryptContext()
    {
        BOOL ret = CryptReleaseContext(m_cryptContext, 0);
        assert(ret);
    }

    HCRYPTPROV CCryptContext::Get() const
    {
        return m_cryptContext;
    }


    CCryptKey::CCryptKey(HCRYPTKEY cryptKey)
        : m_key(cryptKey)
    {

    }
    CCryptKey::~CCryptKey()
    {
        if (m_key)
        {
            CryptDestroyKey(m_key);
        }

    }

    CCryptKey::CCryptKey(CCryptKey&& other)
    {
        this->m_key = other.release();
    }
    CCryptKey& CCryptKey::operator=(CCryptKey&& other)
    {
        this->m_key = other.release();
        return *this;
    }

    HCRYPTKEY CCryptKey::get() const
    {
        return m_key;
    }

    void CCryptKey::reset(HCRYPTKEY cryptKey)
    {
        if (m_key)
        {
            CryptDestroyKey(m_key);
        }
        m_key = cryptKey;
    }

    HCRYPTKEY CCryptKey::release()
    {
        HCRYPTKEY key = m_key;
        m_key = NULL;
        return key;
    }

    HCRYPTKEY * CCryptKey::operator&()
    {
        return &m_key;
    }




    CCryptKeyHash::CCryptKeyHash(HCRYPTPROV hCryptContext, ALG_ID algorithmId, HCRYPTKEY key, DWORD flags)
        : m_cryptHash(NULL)
    {
        if (!CryptCreateHash(hCryptContext, algorithmId, key, flags, &m_cryptHash))
        {
            int error = GetLastError();
            throw std::runtime_error(util::generate_errorMsg("An error has occurred during CryptCreateHash!", error));
        }
    }
    CCryptKeyHash::~CCryptKeyHash()
    {
        BOOL ret = CryptDestroyHash(m_cryptHash);
        assert(ret);
    }

    HCRYPTHASH CCryptKeyHash::Get() const
    {
        return m_cryptHash;
    }

}
  

