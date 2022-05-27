#include <stdio.h>
#include "miniHook.h"
int WINAPI MyMessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType);

void Myprintf();
void hookMyprintf();

typedef int (WINAPI* pMsg)(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType);

miniHook h(MessageBoxA, MyMessageBoxA);
miniHook h2(Myprintf, hookMyprintf);

int WINAPI MyMessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType) {
    return ((pMsg)h.GetBridge())(0, "b", "a", MB_OK);
}
void hookMyprintf() {//需要禁止编译器自动inline
    printf("hook Myprintf %p\n", h2.GetBridge());
}
void Myprintf() {
    printf("Myprintf\n");
}

int main()
{
    Myprintf();
    h2.Stop();
    Myprintf();
    h2.Start();
    Myprintf();

	MessageBoxA(0, "aaaa", "bbbb", MB_OK);
    h.Stop();
    MessageBoxA(0, "unhook", "2", MB_OK);
    h.Start();
    MessageBoxA(0, "hook", "3", MB_OK);
    h.Stop();
    MessageBoxA(0, "unhook", "4", MB_OK);
    h.Start();
}