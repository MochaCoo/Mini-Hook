#include <stdio.h>
#include "miniHook.h"
int WINAPI MyMessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType);
typedef int (WINAPI* pMsg)(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType);
miniHook h(MessageBoxA, MyMessageBoxA);
int WINAPI MyMessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType) {
    return ((pMsg)h.GetBridge())(0, "b", "a", MB_OK);
}

int main()
{
	MessageBoxA(0, "aaaa", "bbbb", MB_OK);
    h.Stop();
    MessageBoxA(0, "unhook", "2", MB_OK);
    h.Start();
    MessageBoxA(0, "hook", "3", MB_OK);
    h.Stop();
    MessageBoxA(0, "unhook", "4", MB_OK);
    h.Start();
}