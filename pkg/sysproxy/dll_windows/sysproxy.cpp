#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include <Windows.h>
#include <WinInet.h>
#include <atlstr.h>
#include "sysproxy.h"

LPWSTR stringToLPWSTR(std::string orig)
{
	wchar_t* wcstring = 0;
	try
	{
		size_t origsize = orig.length() + 1;
		const size_t newsize = 100;
		size_t convertedChars = 0;
		if (orig == "")
		{
			wcstring = (wchar_t*)malloc(0);
			mbstowcs_s(&convertedChars, wcstring, origsize, orig.c_str(), _TRUNCATE);
		}
		else
		{
			wcstring = (wchar_t*)malloc(sizeof(wchar_t) * (orig.length() - 1));
			mbstowcs_s(&convertedChars, wcstring, origsize, orig.c_str(), _TRUNCATE);
		}
	}
	catch (std::exception e)
	{
	}
	return wcstring;
}


// from https://github.com/Qv2ray/Qv2ray/blob/master/src/components/proxy/QvProxyConfigurator.cpp
//#define NO_CONST(expr) const_cast<wchar_t *>(expr)
// static auto DEFAULT_CONNECTION_NAME = NO_CONST(L"DefaultConnectionSettings");
///
/// INTERNAL FUNCTION
bool __QueryProxyOptions()
{
	INTERNET_PER_CONN_OPTION_LIST List;
	INTERNET_PER_CONN_OPTION Option[5];
	//
	unsigned long nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
	Option[0].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
	Option[1].dwOption = INTERNET_PER_CONN_AUTODISCOVERY_FLAGS;
	Option[2].dwOption = INTERNET_PER_CONN_FLAGS;
	Option[3].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
	Option[4].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
	//
	List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
	List.pszConnection = nullptr; // NO_CONST(DEFAULT_CONNECTION_NAME);
	List.dwOptionCount = 5;
	List.dwOptionError = 0;
	List.pOptions = Option;

	if (!InternetQueryOption(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
	{
		std::cout << "InternetQueryOption failed, GLE=" + GetLastError() << std::endl;
	}

	std::cout << "System default proxy info:" << std::endl;

	if (Option[0].Value.pszValue != nullptr)
	{
		std::cout << CW2A(Option[0].Value.pszValue) << std::endl;
	}

	if ((Option[2].Value.dwValue & PROXY_TYPE_AUTO_PROXY_URL) == PROXY_TYPE_AUTO_PROXY_URL)
	{
		std::cout << "PRPXY_TYPE_AUTO_PROXY_URL" << std::endl;
	}

	if ((Option[2].Value.dwValue & PROXY_TYPE_AUTO_DETECT) == PROXY_TYPE_AUTO_DETECT)
	{
		std::cout << "PROXY_TYPE_AUTO_DETECT" << std::endl;
	}

	if ((Option[2].Value.dwValue & PROXY_TYPE_DIRECT) == PROXY_TYPE_DIRECT)
	{
		std::cout << "PROXY_TYPE_DIRECT" << std::endl;
	}

	if ((Option[2].Value.dwValue & PROXY_TYPE_PROXY) == PROXY_TYPE_PROXY)
	{
		std::cout << "PROXY_TYPE_PROXY" << std::endl;
	}

	if (!InternetQueryOption(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
	{
		std::cout << "InternetQueryOption failed,GLE=" + GetLastError() << std::endl;
	}

	if (Option[4].Value.pszValue != nullptr)
	{
		std::cout << CW2A(Option[4].Value.pszValue) << std::endl;
	}

	INTERNET_VERSION_INFO Version;
	nSize = sizeof(INTERNET_VERSION_INFO);
	InternetQueryOption(nullptr, INTERNET_OPTION_VERSION, &Version, &nSize);

	if (Option[0].Value.pszValue != nullptr)
	{
		GlobalFree(Option[0].Value.pszValue);
	}

	if (Option[3].Value.pszValue != nullptr)
	{
		GlobalFree(Option[3].Value.pszValue);
	}

	if (Option[4].Value.pszValue != nullptr)
	{
		GlobalFree(Option[4].Value.pszValue);
	}

	return false;
}

bool __SetProxyOptions(LPWSTR proxy_full_addr, bool isPAC)
{
	INTERNET_PER_CONN_OPTION_LIST list;
	BOOL bReturn;
	DWORD dwBufSize = sizeof(list);
	// Fill the list structure.
	list.dwSize = sizeof(list);
	// NULL == LAN, otherwise connectoid name.
	list.pszConnection = nullptr;

	if (isPAC)
	{
		//LOG(MODULE_PROXY, "Setting system proxy for PAC")
		//
		list.dwOptionCount = 2;
		list.pOptions = new INTERNET_PER_CONN_OPTION[2];

		// Ensure that the memory was allocated.
		if (nullptr == list.pOptions)
		{
			// Return FALSE if the memory wasn't allocated.
			return FALSE;
		}

		// Set flags.
		list.pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
		list.pOptions[0].Value.dwValue = PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL;
		// Set proxy name.
		list.pOptions[1].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
		list.pOptions[1].Value.pszValue = proxy_full_addr;
	}
	else
	{
		std::cout << "Setting system proxy for Global Proxy" << std::endl;
		list.dwOptionCount = 3;
		list.pOptions = new INTERNET_PER_CONN_OPTION[3];

		if (nullptr == list.pOptions)
		{
			return false;
		}

		// Set flags.
		list.pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
		list.pOptions[0].Value.dwValue = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY;
		// Set proxy name.
		list.pOptions[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
		list.pOptions[1].Value.pszValue = proxy_full_addr;
		// Set proxy override.
		list.pOptions[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
		auto localhost = L"localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*";
		list.pOptions[2].Value.pszValue = const_cast<wchar_t*>(localhost);
	}

	// Set the options on the connection.
	bReturn = InternetSetOption(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize);
	delete[] list.pOptions;
	InternetSetOption(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
	InternetSetOption(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
	return bReturn;
}


void SetSystemProxy(char* addressg, char* httpPortg, char* socksPortg)
{
	std::string address = std::string(addressg);
	std::string httpPort = std::string(httpPortg);
	std::string socksPort = std::string(socksPortg);

	std::cout << "Setting up System Proxy" << std::endl;

	bool hasHTTP = (httpPort.size() > 0);
	bool hasSOCKS = (socksPort.size() > 0);

	if (!hasHTTP && !hasSOCKS)
	{
		std::cout << "Nothing" << std::endl;
		return;
	}

	if (hasHTTP)
	{
		std::cout << "HTTP PORT: " << httpPort << std::endl;
	}

	if (hasSOCKS)
	{
		std::cout << "SOCKS PORT: " << socksPort << std::endl;
	}

	const auto scheme = (hasHTTP ? "" : "socks5://");
	std::string __a = scheme + address + ":" + (hasHTTP ? httpPort : socksPort);

	std::cout << "Windows proxy string: " << __a << std::endl;

	__QueryProxyOptions();

	if (!__SetProxyOptions(stringToLPWSTR(__a), false))
	{
		std::cout << "Failed to set proxy." << std::endl;
	}

	__QueryProxyOptions();
}

void ClearSystemProxy()
{
	std::cout << "Clearing System Proxy" << std::endl;
	std::cout << "Cleaning system proxy settings." << std::endl;
	INTERNET_PER_CONN_OPTION_LIST list;
	BOOL bReturn;
	DWORD dwBufSize = sizeof(list);
	// Fill out list struct.
	list.dwSize = sizeof(list);
	// nullptr == LAN, otherwise connectoid name.
	list.pszConnection = nullptr;
	// Set three options.
	list.dwOptionCount = 1;
	list.pOptions = new INTERNET_PER_CONN_OPTION[list.dwOptionCount];

	// Make sure the memory was allocated.
	if (nullptr == list.pOptions)
	{
		// Return FALSE if the memory wasn't allocated.
		std::cout << "Failed to allocat memory in DisableConnectionProxy()" << std::endl;
	}

	// Set flags.
	list.pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
	list.pOptions[0].Value.dwValue = PROXY_TYPE_DIRECT;
	//
	// Set the options on the connection.
	bReturn = InternetSetOption(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize);
	delete[] list.pOptions;
	InternetSetOption(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
	InternetSetOption(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}
