
/*

	GNU AFFERO GENERAL PUBLIC LICENSE
        Version 3, 19 November 2007
	Copyrights © Numéro du projet sept sérine.
	author: sérine

*/


#include "stdafx.h"
#include "Enumarate.h"


#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <lm.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")

/*
	EnumarateShare,
	purpose: chack if the connection to the share
	is possible, if it is, let us know where can we drop	
	The payload, supports MsBrowse protocol
	Smb V1 || 2 || 3.

*/

void EnumarateShare(
	LPWSTR lpszServer
	)
{
	PSHARE_INFO_502 BufPtr, p;
	NET_API_STATUS res;
	
	DWORD er = 0, tr = 0, resume = 0, i;
	
	// For Debugging reasons,
	// TODO: make the routine returna list of possible
	// paths to drop the payload on the remote share for installation.
	
	printf("Share:              Local Path:                   Uses:   Descriptor:\n"); 
	printf("---------------------------------------------------------------------\n");
	do 
	{
		res = NetShareEnum(
			lpszServer,
			502,
			(LPBYTE *)&BufPtr,
			MAX_PREFERRED_LENGTH,
			&er,
			&tr,
			&resume
		);
		if (
			res == ERROR_SUCCESS || res == ERROR_MORE_DATA
			)
		{
			p = BufPtr;
			for (i = 1; i <= er; i++)
			{
				printf(
					"%-20S%-30S%-8u",
					p->shi502_netname,
					p->shi502_path,
					p->shi502_current_uses
				);
				if (
					IsValidSecurityDescriptor(
						p->shi502_security_descriptor
					)
				)
					printf("Yes\n");  // Can we drop there?
				else
					printf("No\n");
				p++;
			}
			NetApiBufferFree(BufPtr);
		}
		else
			printf("Error: %ld\n", res);
	}
	while (res == ERROR_MORE_DATA);
	return;
}

