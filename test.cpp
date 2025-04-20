#include <stdio.h>

#include "hooker.h"

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

int main()
{
    NormalFunction();
    Hooker::Hook(NormalFunction, NormalFunctionHook);
    NormalFunction();
    printf("Num: %i\n", AddNums(34, 35));
    Hooker::Hook(AddNums, AddNumsHook);
    printf("Num: %i\n", AddNums(210, 2));
}
