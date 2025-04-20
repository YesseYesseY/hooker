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

void NormalFunction()
{
    printf("Hello, World!\n");
}

void NormalFunctionHook()
{
    printf("Hello, Hook!\n");
}

int MessageBoxHook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return MessageBoxW(hWnd, L"Get hooked", L"xd", MB_CANCELTRYCONTINUE);
}

int main()
{
    NormalFunction();
    Hooker::Hook(NormalFunction, NormalFunctionHook);
    NormalFunction();
    printf("Num: %i\n", AddNums(34, 35));
    Hooker::Hook(AddNums, AddNumsHook);
    printf("Num: %i\n", AddNums(210, 2));

    Hooker::Hook(MessageBoxA, MessageBoxHook);
    MessageBoxA(0, "This is a normal messagebox :)", "Normal", 0);
}
