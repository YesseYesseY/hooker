#pragma once
#include <Windows.h>
#include <cstdio>
#include <cstring>

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

    void Hook(void* func_to_hook, void* new_func)
    {
        DWORD temp;
        VirtualProtect(func_to_hook, 5, PAGE_EXECUTE_READWRITE, &temp);
        
        uint8* func_as_arr = ((uint8*)func_to_hook);
        
        if (func_as_arr[0] == 0xE9)
        {
            func_to_hook = (void*)((uint64)func_to_hook + 5 + *(int32*)&func_as_arr[1]);
            func_as_arr = (uint8*)func_to_hook;

            VirtualProtect(func_to_hook, 5, PAGE_EXECUTE_READWRITE, &temp);
        }

        void* relay = AllocatePageNearAddress(func_to_hook, 5);
        uint8* relay_as_arr = (uint8*)relay;
        relay_as_arr[0] = 0x49;
        relay_as_arr[1] = 0xBB;
        *(uint64*)&relay_as_arr[2] = (uint64)new_func;
        relay_as_arr[10] = 0x41;
        relay_as_arr[11] = 0xFF;
        relay_as_arr[12] = 0xE3;

        func_as_arr[0] = 0xE9;
        *(int32*)&func_as_arr[1] = (uint64)relay - ((uint64)func_to_hook + 5);
    }
}
