#include "stdafx.h"
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <assert.h>

#include <vector>
#include <string>

#include "Utils.h"
#include "Config.h"

#include "SDServer.h"

static BOOL IsCommand(const char * name, char * command, size_t len)
{
	size_t namelen = strlen(name);

	if (len < namelen + 1)
		return FALSE;

	return (0 == stricmp(name, command));
}

typedef int (* PDSGetPluginX)(PDSClientPlugin pplugin);

static int DSGetPugin(const char * plugin_name, PDSClientPlugin pplugin)
{
	char name[4096];
	PDSGetPluginX pDSGetPluginX;
	HINSTANCE hModule = GetModuleHandle(NULL);
	if (hModule == NULL) {
		return -1;
	}

	name[sizeof(name) - 1] = 0;
	strncpy(name, "DSGetPlugin_", sizeof(name));
	strncat(name, plugin_name, sizeof(name));
	if (name[sizeof(name) - 1] != 0) {
		return -1;
	}

	pDSGetPluginX = (PDSGetPluginX)GetProcAddress(hModule, name);
	if (pDSGetPluginX == NULL) {
		return -1;
	}

	return pDSGetPluginX(pplugin);
}

HANDLE CreateShareMutex(BOOL bOwner, LPCTSTR lpName)
{
	DWORD LastError;
    EXPLICIT_ACCESS ea[1];
	PSID pAdminSID = NULL;
    PSID pEveryoneSID = NULL;

    PACL pACL = NULL;
	HANDLE hMutex = NULL;
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    
	do {
        if (!AllocateAndInitializeSid(&SIDAuthWorld,
			1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID )) {
            LastError = GetLastError();
            break;
        }

        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
        ea[0].grfAccessPermissions = MUTEX_ALL_ACCESS;
        ea[0].grfAccessMode  = SET_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[0].Trustee.ptstrName  = (LPTSTR) pEveryoneSID;
		
        LastError = SetEntriesInAcl(1, ea, NULL, &pACL);
        if (ERROR_SUCCESS != LastError) {
            break;
        }
		
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (NULL == pSD){
            LastError = GetLastError();
            break;
        }

        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) { 
            LastError = GetLastError();
            break;
        }

        if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE)) { 
            LastError = GetLastError();
            break;
        }
		
        // Initialize a security attributes structure.
        sa.nLength = sizeof( SECURITY_ATTRIBUTES );
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;
		
        ////////////////
        hMutex = CreateMutex(&sa, bOwner, lpName);
        if (NULL == hMutex) {
            LastError = GetLastError();
            break;
        }
    } while( 0 );
	
    if (pEveryoneSID) {
        FreeSid( pEveryoneSID );
    }
    
	if (pACL) {
        LocalFree( pACL );
    }

    if (pSD) {
        LocalFree(pSD);
    }

	if (hMutex == NULL) {
		SetLastError(LastError);
	}

    return hMutex;
}

int Delivery(HANDLE hEvent, const char * Request, size_t len)
{
	int error;
	DWORD state;
	HANDLE hMutex = NULL;
	DS_ASSERT(hEvent != NULL);
	std::vector<char> request(len);
	std::vector<DSClientPlugin> plugins;

	const char * pluginNames[] = {
		"FlowControl", "Network", "TcpTransfer", NULL
	};

	hMutex = CreateShareMutex(TRUE, MUTEX_NAME);

	for (int i = 0; pluginNames[i] != NULL; i++) {
		DSClientPlugin dsplugin;
		error = DSGetPugin(pluginNames[i], &dsplugin);
		if (error != 0) {
			continue;
		}
		plugins.push_back(dsplugin);
	}

	std::vector<DSClientPlugin>::iterator iter;
	for (iter = plugins.begin(); iter != plugins.end(); ++iter) {
		if (iter->initialize == NULL) {
			continue;
		}
		error = iter->initialize();
		DS_ASSERT (error == 0);
	}

	for (iter = plugins.begin(); iter != plugins.end(); ++iter) {
		if (iter->start == NULL) {
			continue;
		}
		error = iter->start();
		DS_ASSERT (error == 0);
	}

	
	for ( ; ; ) {
		state = WaitForSingleObject(hEvent, INFINITE);
		if (state == WAIT_OBJECT_0) {
			strncpy(&request[0], Request, len);
			ResetEvent(hEvent);

			if (IsCommand("Quit", &request[0], len)) {
				printf("Delivery Thread receive quit command\n");
				break;
			}

			if (IsCommand("Reload", &request[0], len)) {
				printf("Reload Command\n");
				//ReloadTaskList();
			}
		}
	}

	for (iter = plugins.begin(); iter != plugins.end(); ++iter) {
		if (iter->stop == NULL) {
			continue;
		}
		error = iter->stop();
		DS_ASSERT (error == 0);
	}

	for (iter = plugins.begin(); iter != plugins.end(); ++iter) {
		if (iter->clean == NULL) {
			continue;
		}
		error = iter->clean();
		DS_ASSERT (error == 0);
	}
	
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	return 0;
}
