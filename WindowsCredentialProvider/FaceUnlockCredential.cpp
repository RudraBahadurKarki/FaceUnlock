#include "FaceUnlockCredential.h"

#include <windows.h>
#include <credentialprovider.h>
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

FaceUnlockCredential::FaceUnlockCredential()
    : _refCount(1),
      _events(nullptr)
{
}

// ============================================================
// Destructor
// ============================================================

FaceUnlockCredential::~FaceUnlockCredential()
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }
}
void FaceUnlockCredential::SetStatus(PCWSTR status)
{
    if (!_events || !status)
        return;

    PWSTR text = CopyStringToCoTaskMem(status);

    if (!text)
        return;

    _events->SetFieldString(
        this,
        2,
        text);

    CoTaskMemFree(text);
}
// ============================================================
// IUnknown
// ============================================================

STDMETHODIMP FaceUnlockCredential::QueryInterface(
    REFIID riid,
    void **ppv)
{
    if (!ppv)
        return E_POINTER;

    *ppv = nullptr;

    if (riid == IID_IUnknown ||
        riid == __uuidof(ICredentialProviderCredential))
    {
        *ppv =
            static_cast<ICredentialProviderCredential *>(this);

        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG)
FaceUnlockCredential::AddRef()
{
    return InterlockedIncrement(&_refCount);
}

STDMETHODIMP_(ULONG)
FaceUnlockCredential::Release()
{
    LONG count =
        InterlockedDecrement(&_refCount);

    if (count == 0)
        delete this;

    return count;
}

// ============================================================
// Advise
// ============================================================

STDMETHODIMP FaceUnlockCredential::Advise(
    ICredentialProviderCredentialEvents *pcpce)
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    if (pcpce)
    {
        _events = pcpce;
        _events->AddRef();
    }

    return S_OK;
}

// ============================================================
// UnAdvise
// ============================================================

STDMETHODIMP FaceUnlockCredential::UnAdvise()
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    return S_OK;
}

// ============================================================
// Selected
// ============================================================

STDMETHODIMP FaceUnlockCredential::SetSelected(
    BOOL *pbAutoLogon)
{
    if (!pbAutoLogon)
        return E_POINTER;

    *pbAutoLogon = FALSE;

    SetStatus(L"FaceUnlock selected");

    return S_OK;
}

// ============================================================
// Deselected
// ============================================================

STDMETHODIMP FaceUnlockCredential::SetDeselected()
{
    return S_OK;
}

// ============================================================
// Field State
//
// 0 = title
// 1 = instruction
// 2 = status
// 3 = submit button
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    if (!pcpfs || !pcpfis)
        return E_POINTER;

    switch (dwFieldID)
    {
    case 0:
    case 1:
    case 2:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        return S_OK;

    case 3:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        return S_OK;

    default:
        return E_INVALIDARG;
    }
}

// ============================================================
// String Values
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetStringValue(
    DWORD dwFieldID,
    PWSTR *ppwsz)
{
    if (!ppwsz)
        return E_POINTER;

    *ppwsz = nullptr;

    PCWSTR text = nullptr;

    switch (dwFieldID)
    {
    case 0:
        text = L"FaceUnlock";
        break;

    case 1:
        text = L"Use iPhone Face ID";
        break;

    case 2:
        text = L"Ready";
        break;

    default:
        return E_INVALIDARG;
    }

    *ppwsz =
        CopyStringToCoTaskMem(text);

    if (!*ppwsz)
        return E_OUTOFMEMORY;

    return S_OK;
}

// ============================================================
// Bitmap
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetBitmapValue(
    DWORD dwFieldID,
    HBITMAP *phbmp)
{
    UNREFERENCED_PARAMETER(dwFieldID);

    if (!phbmp)
        return E_POINTER;

    *phbmp = nullptr;

    return E_NOTIMPL;
}

// ============================================================
// Checkbox
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetCheckboxValue(
    DWORD dwFieldID,
    BOOL *pbChecked,
    PWSTR *ppwszLabel)
{
    UNREFERENCED_PARAMETER(dwFieldID);

    if (!pbChecked || !ppwszLabel)
        return E_POINTER;

    *pbChecked = FALSE;
    *ppwszLabel = nullptr;

    return E_NOTIMPL;
}

// ============================================================
// Submit Button
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD *pdwAdjacentTo)
{
    if (!pdwAdjacentTo)
        return E_POINTER;

    if (dwFieldID != 3)
        return E_INVALIDARG;

    *pdwAdjacentTo = 2;

    return S_OK;
}

// ============================================================
// Set String
// ============================================================

STDMETHODIMP FaceUnlockCredential::SetStringValue(
    DWORD dwFieldID,
    PCWSTR pwz)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pwz);

    return E_NOTIMPL;
}

// ============================================================
// Set Checkbox
// ============================================================

STDMETHODIMP FaceUnlockCredential::SetCheckboxValue(
    DWORD dwFieldID,
    BOOL bChecked)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

// ============================================================
// ComboBox
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetComboBoxValueCount(
    DWORD dwFieldID,
    DWORD *pcItems,
    DWORD *pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);

    if (!pcItems || !pdwSelectedItem)
        return E_POINTER;

    *pcItems = 0;
    *pdwSelectedItem = 0;

    return S_OK;
}

STDMETHODIMP FaceUnlockCredential::GetComboBoxValueAt(
    DWORD dwFieldID,
    DWORD dwItem,
    PWSTR *ppwszItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);

    if (!ppwszItem)
        return E_POINTER;

    *ppwszItem = nullptr;

    return E_INVALIDARG;
}

STDMETHODIMP FaceUnlockCredential::SetComboBoxSelectedValue(
    DWORD dwFieldID,
    DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);

    return E_NOTIMPL;
}

// ============================================================
// Command Link
// ============================================================

STDMETHODIMP FaceUnlockCredential::CommandLinkClicked(
    DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);

    return E_NOTIMPL;
}

// ============================================================
// GetSerialization
// ============================================================

STDMETHODIMP FaceUnlockCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
    PWSTR *ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    if (!pcpgsr || !pcpcs)
        return E_POINTER;

    ZeroMemory(
        pcpcs,
        sizeof(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION));

    *pcpgsr =
        CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    if (ppwszOptionalStatusText)
        *ppwszOptionalStatusText = nullptr;

    if (pcpsiOptionalStatusIcon)
        *pcpsiOptionalStatusIcon = CPSI_NONE;

    // ========================================================
    // TEST
    // ========================================================

    SetStatus(L"FaceUnlock button clicked!");

    OutputDebugStringW(
        L"[FaceUnlock] GetSerialization called.\n");

    return S_OK;
}

// ============================================================
// ReportResult
// ============================================================

STDMETHODIMP FaceUnlockCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR *ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);

    if (ppwszOptionalStatusText)
        *ppwszOptionalStatusText = nullptr;

    if (pcpsiOptionalStatusIcon)
        *pcpsiOptionalStatusIcon = CPSI_NONE;

    return S_OK;
}