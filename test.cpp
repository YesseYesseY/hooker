#include <stdio.h>
#include <Windows.h>

#include "hooker.h"
#include "winuser.h"

int AddNums(int a, int b)
{
    int c = a + b;
    return c;
}

int AddNumsHook(int a, int b)
{
    return a * b;
}
int (*AddNumsOriginal)(int, int) = nullptr;

void NormalFunction()
{
    printf("Hello, World!\n");
}
void NormalFunctionHook()
{
    printf("Hello, Hook!\n");
}

int (*MessageBoxAOriginal)(HWND,LPCSTR,LPCSTR,UINT);
int MessageBoxHook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return MessageBoxAOriginal(hWnd, "Get hooked", "xd", MB_CANCELTRYCONTINUE);
}

int SubNumsBackend(int a, int b)
{
    return a - b;
}
int SubNums(int a, int b)
{
    return SubNumsBackend(a, b);
}
int SubNumsHook(int a, int b)
{
    return a / b;
}
int (*SubNumsOriginal)(int,int) = nullptr;

// FIXME: This fails trampoline hook because the stored bytes has a relative jump
int RandomName(bool yes)
{
    goto yesuwu;
    return 30;
yesuwu:
    return 60;
}

void (*NormalFunctionOriginal)() = nullptr;

int main()
{
    Hooker::SimpleHook NormalSimpleHook(NormalFunction, NormalFunctionHook);
    NormalSimpleHook.CreateHook();
    NormalFunction();
    NormalSimpleHook.RemoveHook();
    NormalFunction();

    printf("SubNum: %i\n", SubNums(34, 35));
    Hooker::Hook(SubNums, SubNumsHook, (void**)&SubNumsOriginal);
    printf("SubNum: %i\n", SubNums(32, 4));
    printf("SubNum: %i\n", SubNumsOriginal(35, 34));

    printf("AddNum: %i\n", AddNums(34, 35));
    Hooker::Hook(AddNums, AddNumsHook, (void**)&AddNumsOriginal, 8);
    printf("AddNum: %i\n", AddNums(210, 2));
    printf("AddNum: %i\n", AddNumsOriginal(191, 1146));

    Hooker::Hook(MessageBoxA, MessageBoxHook, (void**)&MessageBoxAOriginal, 5);
    MessageBoxA(0, "This is a normal messagebox :)", "Normal", 0);
}
