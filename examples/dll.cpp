
#include <windows.h>
#include <iostream>

extern "C" __declspec(dllexport) int AddNumbers(int a, int b)
{
    std::cout << "from dll: " << a+b << "\n";
    return a+b;
}


BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        std::cout << "from dll: pattach\n";
        break;
    case DLL_THREAD_ATTACH:
        std::cout << "from dll: tattach\n";
    case DLL_THREAD_DETACH:
        std::cout << "from dll: tdetach\n";

    case DLL_PROCESS_DETACH:
        std::cout << "from dll: pdetach\n";
        break;
    }
    return TRUE;
}
