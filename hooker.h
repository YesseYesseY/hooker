#pragma once
#include <Windows.h>
#include <cstdio>
#include <cstring>

#ifndef _WIN64
#error There is only support for 64 bit Windows as of now
#endif

namespace Hooker
{
    typedef unsigned char uint8;
    typedef signed int int32;
    typedef unsigned long long uint64;

    // Taken from https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
    void* AllocatePageNearAddress(void* targetAddr, uint64 size)
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        const uint64 PAGE_SIZE = size; // sysInfo.dwPageSize;
    
        uint64 startAddr = (uint64(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
        uint64 minAddr = min(startAddr - 0x7FFFFF00, (uint64)sysInfo.lpMinimumApplicationAddress);
        uint64 maxAddr = max(startAddr + 0x7FFFFF00, (uint64)sysInfo.lpMaximumApplicationAddress);
    
        uint64 startPage = (startAddr - (startAddr % PAGE_SIZE));
    
        uint64 pageOffset = 1;
        while (1)
        {
            uint64 byteOffset = pageOffset * PAGE_SIZE;
            uint64 highAddr = startPage + byteOffset;
    		uint64 lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;
    
            bool needsExit = highAddr > maxAddr && lowAddr < minAddr;
    
            if (highAddr < maxAddr)
            {
                void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (outAddr)
                    return outAddr;
            }
    
            if (lowAddr > minAddr)
            {
                void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (outAddr != nullptr)
                    return outAddr;
            }
    
            pageOffset++;
    
            if (needsExit)
            {
                break;
            }
        }
    
        return nullptr;
    }

    void WriteJmpRelative(void* ptr_to_jmp, void* jmp_destination)
    {
        ((uint8*)ptr_to_jmp)[0] = 0xE9;
        *(int32*)&((uint8*)ptr_to_jmp)[1] = (uint64)jmp_destination - ((uint64)ptr_to_jmp + 5);
    }

    void WriteJmp(void* ptr_to_jmp, void* jmp_destination)
    {
        static uint8 jmptemplate[13] = {0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE3};
        memcpy(ptr_to_jmp, jmptemplate, 13);
        *(uint64*)&((uint8*)ptr_to_jmp)[2] = (uint64)jmp_destination;
    }

    // banger name
    void* JmpUnrelativer(void* ptr_to_jmp)
    {
        return (void*)((uint64)ptr_to_jmp + 5 + *(int32*)&((uint8*)ptr_to_jmp)[1]);
    }

    // For now it's REQUIRED to input bytes_to_store the amount of bytes to store in the relay before jumping
    // You can get it from ida, x64dbg or anything it just needs to be 1. over 5 bytes and 2. cant contain uncomplete instructions
    // Also possible to put -1 and pray to whatever you believe in that there's a sub, rsp after 5 bytes
    void Hook(void* func_to_hook, void* new_func, void** original_function = nullptr, int32 bytes_to_store = -1)
    {
        DWORD temp;
        VirtualProtect(func_to_hook, 5, PAGE_EXECUTE_READWRITE, &temp);
        
        uint8* func_as_arr = ((uint8*)func_to_hook);
        
        if (func_as_arr[0] == 0xE9)
        {
            func_to_hook = JmpUnrelativer(func_to_hook);
            func_as_arr = (uint8*)func_to_hook;

            VirtualProtect(func_to_hook, 5, PAGE_EXECUTE_READWRITE, &temp);
        }

        if (original_function != nullptr)
        {
            // Works sometimes, sometimes not
            static uint8 subrsp[3] = { 0x48, 0x83, 0xEC }; 
            if (bytes_to_store == -1)
            {
                for (int i = 5; i < 50; i++)
                {
                    if (memcmp(&func_as_arr[i], subrsp, 3) == 0)
                    {
                        bytes_to_store = i + 4;
                    }
                }
            }

            if (bytes_to_store < 5)
            {
                printf("bytes_to_store needs to be 5 or more\n");
                return;
            }

            void* trampoline = AllocatePageNearAddress(new_func, 13 + bytes_to_store);
            memcpy(trampoline, func_to_hook, bytes_to_store);
            WriteJmp((void*)((uint64)trampoline + bytes_to_store), (void*)((uint64)func_to_hook + bytes_to_store));
            *original_function = trampoline;
        }

        void* relay = AllocatePageNearAddress(func_to_hook, 13);
        WriteJmp(relay, new_func);

        WriteJmpRelative(func_to_hook, relay);
    }

    class SimpleHook
    {
    public:
        SimpleHook(void* func_to_hook, void* new_func)
        {
            func_location = func_to_hook;
            if (((uint8*)func_to_hook)[0] == 0xE9) // TODO: Change to while?
                func_to_hook = JmpUnrelativer(func_to_hook);

            relay_location = AllocatePageNearAddress(func_to_hook, 13);
            WriteJmp(relay_location, new_func);

            hook_location = new_func;
            hooked = false;
        }

        void CreateHook()
        {
            if (hooked)
                return;

            VirtualProtect(func_location, 5, PAGE_EXECUTE_READWRITE, &prevProtect);
            memcpy(origBytes, func_location, 5);
            WriteJmpRelative(func_location, relay_location);
            hooked = true;
        }

        void RemoveHook()
        {
            if (!hooked)
                return;

            memcpy(func_location, origBytes, 5);
            hooked = false;
        }

    private:
        void* func_location;
        void* hook_location;
        void* relay_location;
        bool hooked;
        DWORD prevProtect;
        uint8 origBytes[5];
    };
}
