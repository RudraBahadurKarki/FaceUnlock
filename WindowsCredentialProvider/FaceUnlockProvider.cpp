#include "FaceUnlockProvider.h"
#include "FaceUnlockCredential.h"

#include <new>
#include <wchar.h>

// ============================================================
// Helper
// ============================================================

static PWSTR CopyStringToCoTaskMem(PCWSTR text)
{
    if (!text)
        return nullptr;

    size_t length = wcslen(text) + 1;

    PWSTR result =
        static_cast<PWSTR>(
            CoTaskMemAlloc(length * sizeof(wchar_t)));

    if (!result)
        return nullptr;

    memcpy(
        result,
        text,
        length * sizeof(wchar_t));

    return result;
}

// ============================================================
// Constructor
// ============================================================

FaceUnlockProvider::FaceUnlockProvider()
    : _refCount(1),
      _credential(nullptr)
{
    _credential = new (std::nothrow) FaceUnlockCredential();
}

// ============================================================
// Destructor
// ============================================================

FaceUnlockProvider::~FaceUnlockProvider()
{
    if (_credential)
    {
        _credential->Release();
        _credential = nullptr;
    }
}

// ============================================================
// IUnknown
// ============================================================

STDMETHODIMP FaceUnlockProvider::QueryInterface(
    REFIID riid,
    void **ppv)
{
    if (!ppv)
        return E_POINTER;

    *ppv = nullptr;

    if (riid == IID_IUnknown ||
        riid == __uuidof(ICredentialProvider))
    {
        *ppv =
            static_cast<ICredentialProvider *>(this);

        AddRef();

        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG)
FaceUnlockProvider::AddRef()
{
    return InterlockedIncrement(&_refCount);
}

STDMETHODIMP_(ULONG)
FaceUnlockProvider::Release()
{
    LONG count =
        InterlockedDecrement(&_refCount);

    if (count == 0)
        delete this;

    return count;
}

// ============================================================
// Usage Scenario
// ============================================================

STDMETHODIMP FaceUnlockProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(dwFlags);

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        return S_OK;

    default:
        return E_NOTIMPL;
    }
}

// ============================================================
// Serialization
// ============================================================

STDMETHODIMP FaceUnlockProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs)
{
    UNREFERENCED_PARAMETER(pcpcs);

    return E_NOTIMPL;
}

// ============================================================
// Advise
// ============================================================

STDMETHODIMP FaceUnlockProvider::Advise(
    ICredentialProviderEvents *pcpe,
    UINT_PTR upAdviseContext)
{
    UNREFERENCED_PARAMETER(pcpe);
    UNREFERENCED_PARAMETER(upAdviseContext);

    return S_OK;
}

STDMETHODIMP FaceUnlockProvider::UnAdvise()
{
    return S_OK;
}

// ============================================================
// Field Descriptors
//
// 0 = Large title
// 1 = Small instruction
// 2 = Small status
// 3 = Submit button
// ============================================================

STDMETHODIMP FaceUnlockProvider::GetFieldDescriptorCount(
    DWORD *pdwCount)
{
    if (!pdwCount)
        return E_POINTER;

    *pdwCount = 4;

    return S_OK;
}

// ============================================================

STDMETHODIMP FaceUnlockProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    if (!ppcpfd)
        return E_POINTER;

    *ppcpfd = nullptr;

    if (dwIndex >= 4)
        return E_INVALIDARG;

    auto *descriptor =
        static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *>(
            CoTaskMemAlloc(
                sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));

    if (!descriptor)
        return E_OUTOFMEMORY;

    ZeroMemory(
        descriptor,
        sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));

    descriptor->dwFieldID = dwIndex;

    PCWSTR label = nullptr;

    switch (dwIndex)
    {
    case 0:
        descriptor->cpft = CPFT_LARGE_TEXT;
        label = L"FaceUnlock";
        break;

    case 1:
        descriptor->cpft = CPFT_SMALL_TEXT;
        label = L"Use iPhone Face ID";
        break;

    case 2:
        descriptor->cpft = CPFT_SMALL_TEXT;
        label = L"Ready";
        break;

    case 3:
        descriptor->cpft = CPFT_SUBMIT_BUTTON;
        label = L"Unlock";
        break;

    default:
        CoTaskMemFree(descriptor);
        return E_INVALIDARG;
    }

    descriptor->pszLabel =
        CopyStringToCoTaskMem(label);

    if (!descriptor->pszLabel)
    {
        CoTaskMemFree(descriptor);
        return E_OUTOFMEMORY;
    }

    *ppcpfd = descriptor;

    return S_OK;
}

// ============================================================
// Credential Count
// ============================================================

STDMETHODIMP FaceUnlockProvider::GetCredentialCount(
    DWORD *pdwCount,
    DWORD *pdwDefault,
    BOOL *pbAutoLogonWithDefault)
{
    if (!pdwCount ||
        !pdwDefault ||
        !pbAutoLogonWithDefault)
    {
        return E_POINTER;
    }

    *pdwCount = 1;

    *pdwDefault =
        CREDENTIAL_PROVIDER_NO_DEFAULT;

    *pbAutoLogonWithDefault = FALSE;

    return S_OK;
}

// ============================================================
// Get Credential
// ============================================================

STDMETHODIMP FaceUnlockProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential **ppcpc)
{
    if (!ppcpc)
        return E_POINTER;

    *ppcpc = nullptr;

    if (dwIndex != 0)
        return E_INVALIDARG;

    if (!_credential)
        return E_OUTOFMEMORY;

    return _credential->QueryInterface(
        __uuidof(ICredentialProviderCredential),
        reinterpret_cast<void **>(ppcpc));
}