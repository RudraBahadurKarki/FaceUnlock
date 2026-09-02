#pragma once

#include <windows.h>
#include <credentialprovider.h>

class FaceUnlockCredential;

class FaceUnlockProvider : public ICredentialProvider
{
public:
    FaceUnlockProvider();
    virtual ~FaceUnlockProvider();

    // IUnknown
    STDMETHODIMP QueryInterface(
        REFIID riid,
        void **ppv);

    STDMETHODIMP_(ULONG)
    AddRef();

    STDMETHODIMP_(ULONG)
    Release();

    // ICredentialProvider
    STDMETHODIMP SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags);

    STDMETHODIMP SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs);

    STDMETHODIMP Advise(
        ICredentialProviderEvents *pcpe,
        UINT_PTR upAdviseContext);

    STDMETHODIMP UnAdvise();

    STDMETHODIMP GetFieldDescriptorCount(
        DWORD *pdwCount);

    STDMETHODIMP GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd);

    STDMETHODIMP GetCredentialCount(
        DWORD *pdwCount,
        DWORD *pdwDefault,
        BOOL *pbAutoLogonWithDefault);

    STDMETHODIMP GetCredentialAt(
        DWORD dwIndex,
        ICredentialProviderCredential **ppcpc);

private:
    LONG _refCount;
    FaceUnlockCredential *_credential;
};