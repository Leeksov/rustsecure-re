/**
 * native_bridge.cpp — Reconstructed source of RustSecure native bridge DLL.
 *
 * This DLL is injected into the Rust game process (RustClient.exe) via manual mapping.
 * It loads the .NET CLR (v4.0.30319) into the game process and invokes
 * RustSecure.Core.Entry.Init() from the managed Core DLL payload.
 *
 * Exports:
 *   Init()                    — stub (returns 0)
 *   InitFromBytes(ptr, size)  — loads Core DLL from byte array via CLR hosting
 *
 * Build: cl /LD /EHsc native_bridge.cpp ole32.lib oleaut32.lib mscoree.lib
 *
 * Reconstructed from IDA Pro decompilation of native_decrypted.dll
 * Original: RustSecure anti-cheat system (https://rustsecure.ru)
 */

#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <oleauto.h>
#include <comdef.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "mscoree.lib")

// CLR interface GUIDs
static const CLSID CLSID_CLRMetaHost =
    {0x9280188D, 0x0E8E, 0x4867, {0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE}};
static const IID IID_ICLRMetaHost =
    {0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
static const IID IID_ICLRRuntimeInfo =
    {0xBD39D1D2, 0xBA2F, 0x486A, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};
static const IID IID_ICorRuntimeHost =
    {0xCB2F6722, 0xAB3A, 0x11D2, {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}};
static const IID IID_mscorlib_AppDomain =
    {0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}};


/**
 * Wraps a raw byte buffer into a SAFEARRAY(VT_UI1) for passing to Assembly.Load().
 */
static SAFEARRAY* CreateSafeArrayFromBytes(const void* data, ULONG size)
{
    SAFEARRAYBOUND bound;
    bound.lLbound = 0;
    bound.cElements = size;

    SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bound);
    if (!psa)
        return nullptr;

    void* pData = nullptr;
    if (FAILED(SafeArrayAccessData(psa, &pData)) || !pData)
    {
        SafeArrayDestroy(psa);
        return nullptr;
    }

    memcpy(pData, data, size);
    SafeArrayUnaccessData(psa);
    return psa;
}


/**
 * Core function: loads .NET CLR into the current process, loads the managed
 * Core DLL from a byte array, and invokes RustSecure.Core.Entry.Init().
 *
 * @param payloadPtr  Pointer to the Core DLL bytes in memory
 * @param payloadSize Size of the Core DLL in bytes
 * @return 0 on success, error code otherwise:
 *         1 = invalid arguments
 *         2 = COM initialization failed
 *         3 = Assembly.Load failed
 *         4 = Type/method resolution failed
 *         5 = Invocation failed
 */
static DWORD CLR_LoadAndInvokeCore(const void* payloadPtr, DWORD payloadSize)
{
    if (!payloadPtr || payloadSize == 0)
        return 1;

    // Initialize COM (STA)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool comInitialized = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) // 0x80010106
        return 2;

    DWORD result = 2;

    ICLRMetaHost*    pMetaHost    = nullptr;
    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    ICorRuntimeHost* pRuntimeHost = nullptr;
    IUnknown*        pAppDomainUnk = nullptr;
    mscorlib::_AppDomain* pAppDomain = nullptr;
    mscorlib::_Assembly*  pAssembly  = nullptr;
    mscorlib::_Type*      pType      = nullptr;
    SAFEARRAY* saPayload = nullptr;
    SAFEARRAY* saArgs    = nullptr;

    // Step 1: Get CLR MetaHost
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr))
        goto cleanup;

    // Step 2: Get .NET 4.0 runtime
    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr))
        goto cleanup;

    // Step 3: Check if runtime is loadable, then start it
    {
        BOOL isLoadable = FALSE;
        hr = pRuntimeInfo->IsLoadable(&isLoadable);
        if (FAILED(hr) || !isLoadable)
            goto cleanup;
    }

    // Step 4: Get the legacy ICorRuntimeHost interface
    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr))
        goto cleanup;

    // Step 5: Start the CLR
    hr = pRuntimeHost->Start();
    if (FAILED(hr))
        goto cleanup;

    // Step 6: Get default AppDomain
    hr = pRuntimeHost->GetDefaultDomain(&pAppDomainUnk);
    if (FAILED(hr))
        goto cleanup;

    hr = pAppDomainUnk->QueryInterface(IID_mscorlib_AppDomain, (LPVOID*)&pAppDomain);
    if (FAILED(hr))
        goto cleanup;

    // Step 7: Wrap payload bytes in SAFEARRAY and load assembly
    saPayload = CreateSafeArrayFromBytes(payloadPtr, payloadSize);
    if (!saPayload)
    {
        result = 3;
        goto cleanup;
    }

    hr = pAppDomain->Load_3(saPayload, &pAssembly);
    if (FAILED(hr) || !pAssembly)
    {
        result = 3;
        goto cleanup;
    }

    // Step 8: Get type "RustSecure.Core.Entry"
    {
        BSTR bstrTypeName = SysAllocString(L"RustSecure.Core.Entry");
        if (!bstrTypeName)
        {
            result = 4;
            goto cleanup;
        }

        hr = pAssembly->GetType_2(bstrTypeName, &pType);
        SysFreeString(bstrTypeName);

        if (FAILED(hr) || !pType)
        {
            result = 4;
            goto cleanup;
        }
    }

    // Step 9: Invoke "Init" method (static, no arguments)
    {
        saArgs = SafeArrayCreateVector(VT_VARIANT, 0, 0);
        if (!saArgs)
        {
            result = 5;
            goto cleanup;
        }

        VARIANT vtEmpty;
        VariantInit(&vtEmpty);
        vtEmpty.vt = VT_EMPTY;

        VARIANT vtResult;
        VariantInit(&vtResult);

        BSTR bstrMethodName = SysAllocString(L"Init");
        if (!bstrMethodName)
        {
            result = 5;
            goto cleanup;
        }

        hr = pType->InvokeMember_3(
            bstrMethodName,
            static_cast<mscorlib::BindingFlags>(
                mscorlib::BindingFlags_InvokeMethod |
                mscorlib::BindingFlags_Static |
                mscorlib::BindingFlags_Public),
            nullptr,    // binder
            vtEmpty,    // target (null for static)
            saArgs,     // args
            &vtResult
        );

        SysFreeString(bstrMethodName);
        VariantClear(&vtResult);

        result = SUCCEEDED(hr) ? 0 : (DWORD)hr;
    }

cleanup:
    if (saArgs)       SafeArrayDestroy(saArgs);
    if (saPayload)    SafeArrayDestroy(saPayload);
    if (pType)        pType->Release();
    if (pAssembly)    pAssembly->Release();
    if (pAppDomain)   pAppDomain->Release();
    if (pAppDomainUnk) pAppDomainUnk->Release();
    if (pRuntimeHost) pRuntimeHost->Release();
    if (pRuntimeInfo) pRuntimeInfo->Release();
    if (pMetaHost)    pMetaHost->Release();
    if (comInitialized) CoUninitialize();

    return result;
}


// ============================================================
//  Exported functions
// ============================================================

extern "C" {

/**
 * Init — stub export (ordinal 1).
 * Not used in the injection flow; InitFromBytes is the real entry.
 */
__declspec(dllexport) DWORD __stdcall Init()
{
    return 0;
}

/**
 * InitFromBytes — main entry point (ordinal 2).
 * Called by the loader via CreateRemoteThread after manual-mapping this DLL.
 *
 * @param payloadPtr  Pointer to RustSecure.Core.dll bytes
 * @param payloadSize Size in bytes
 * @return 0 on success
 */
__declspec(dllexport) DWORD __stdcall InitFromBytes(const void* payloadPtr, DWORD payloadSize)
{
    return CLR_LoadAndInvokeCore(payloadPtr, payloadSize);
}

}  // extern "C"


/**
 * DLL entry point.
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hModule);
    return TRUE;
}
