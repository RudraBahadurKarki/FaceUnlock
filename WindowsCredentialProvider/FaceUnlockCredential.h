#pragma once

#include <windows.h>
#include <credentialprovider.h>

class FaceUnlockCredential : public ICredentialProviderCredential
{
public:
    FaceUnlockCredential();
    virtual ~FaceUnlockCredential();

    // IUnknown
    STDMETHODIMP QueryInterface(
        REFIID riid,
        void **ppv);

    STDMETHODIMP_(ULONG)
    AddRef();
    STDMETHODIMP_(ULONG)
    Release();

    // ICredentialProviderCredential

    STDMETHODIMP Advise(
        ICredentialProviderCredentialEvents *pcpce);

    STDMETHODIMP UnAdvise();

    STDMETHODIMP SetSelected(
        BOOL *pbAutoLogon);

    STDMETHODIMP SetDeselected();

    STDMETHODIMP GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    STDMETHODIMP GetStringValue(
        DWORD dwFieldID,
        PWSTR *ppwsz);

    STDMETHODIMP GetBitmapValue(
        DWORD dwFieldID,
        HBITMAP *phbmp);

    STDMETHODIMP GetCheckboxValue(
        DWORD dwFieldID,
        BOOL *pbChecked,
        PWSTR *ppwszLabel);

    STDMETHODIMP GetSubmitButtonValue(
        DWORD dwFieldID,
        DWORD *pdwAdjacentTo);

    STDMETHODIMP SetStringValue(
        DWORD dwFieldID,
        PCWSTR pwz);

    STDMETHODIMP SetCheckboxValue(
        DWORD dwFieldID,
        BOOL bChecked);
    STDMETHODIMP GetComboBoxValueCount(
        DWORD dwFieldID,
        DWORD *pcItems,
        DWORD *pdwSelectedItem);

    STDMETHODIMP GetComboBoxValueAt(
        DWORD dwFieldID,
        DWORD dwItem,
        PWSTR *ppwszItem);

    STDMETHODIMP SetComboBoxSelectedValue(
        DWORD dwFieldID,
        DWORD dwSelectedItem);

    STDMETHODIMP CommandLinkClicked(
        DWORD dwFieldID);

    STDMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
        PWSTR *ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

    STDMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR *ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

private:
    LONG _refCount;

    ICredentialProviderCredentialEvents *_events;

    void SetStatus(PCWSTR status);
};