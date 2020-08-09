#pragma once
#include <iostream>

#ifdef SYSPROXY_EXPORTS
#define SYSPROXY_API __declspec(dllexport)
#else
#define SYSPROXY_API __declspec(dllimport)
#endif

extern "C" SYSPROXY_API void SetSystemProxy(char* addressg, char* httpPortg, char* socksPortg);
extern "C" SYSPROXY_API void ClearSystemProxy();
