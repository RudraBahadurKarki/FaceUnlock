#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>

#include "FaceUnlockProvider.h"


// ==================================================
// CLSID
// ==================================================

static const CLSID CLSID_FaceUnlockProvider =
{
    0x8f4e4f21,
    0x5c31,
    0x4e7d,
    { 0x91, 0x42, 0x7a, 0x63, 0x18, 0x29, 0x55, 0x10 }
};


// ==================================================
// DLL reference count
// ==================================================

long g_cDllRef = 0;


// ==================================================
// Class Factory
// ==================================================

class FaceUnlockClassFactory :
    public IClassFactory
{
public:

    FaceUnlockClassFactory()
        : _refCount(1)
    {
        InterlockedIncrement(&g_cDllRef);
    }


    virtual ~FaceUnlockClassFactory()
    {
        InterlockedDecrement(&g_cDllRef);
    }


    // ----------------------------------------------
    // IUnknown
    // ----------------------------------------------

    STDMETHODIMP QueryInterface(
        REFIID riid,
        void** ppv)
    {
        if (!ppv)
            return E_POINTER;

        *ppv = nullptr;

        if (riid == IID_IUnknown ||
            riid == IID_IClassFactory)
        {
            *ppv =
                static_cast<IClassFactory*>(this);

            AddRef();

            return S_OK;
        }

        return E_NOINTERFACE;
    }


    STDMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_refCount);
    }


    STDMETHODIMP_(ULONG) Release()
    {
        LONG count =
            InterlockedDecrement(&_refCount);

        if (count == 0)
            delete this;

        return count;
    }


    // ----------------------------------------------
    // IClassFactory
    // ----------------------------------------------

    STDMETHODIMP CreateInstance(
        IUnknown* pUnkOuter,
        REFIID riid,
        void** ppv)
    {
        if (!ppv)
            return E_POINTER;

        *ppv = nullptr;

        if (pUnkOuter != nullptr)
            return CLASS_E_NOAGGREGATION;

        FaceUnlockProvider* provider =
            new FaceUnlockProvider();

        if (!provider)
            return E_OUTOFMEMORY;

        HRESULT hr =
            provider->QueryInterface(
                riid,
                ppv
            );

        provider->Release();

        return hr;
    }


    STDMETHODIMP LockServer(
        BOOL fLock)
    {
        if (fLock)
            InterlockedIncrement(&g_cDllRef);
        else
            InterlockedDecrement(&g_cDllRef);

        return S_OK;
    }


private:

    LONG _refCount;
};


// ==================================================
// DLL Entry Point
// ==================================================

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
    }

    return TRUE;
}


// ==================================================
// DllGetClassObject
// ==================================================

STDAPI DllGetClassObject(
    REFCLSID rclsid,
    REFIID riid,
    LPVOID* ppv)
{
    if (!ppv)
        return E_POINTER;

    *ppv = nullptr;

    if (rclsid != CLSID_FaceUnlockProvider)
        return CLASS_E_CLASSNOTAVAILABLE;

    FaceUnlockClassFactory* factory =
        new FaceUnlockClassFactory();

    if (!factory)
        return E_OUTOFMEMORY;

    HRESULT hr =
        factory->QueryInterface(
            riid,
            ppv
        );

    factory->Release();

    return hr;
}


// ==================================================
// DllCanUnloadNow
// ==================================================

STDAPI DllCanUnloadNow()
{
    return
        (g_cDllRef == 0)
        ? S_OK
        : S_FALSE;
}