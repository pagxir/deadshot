#include "stdafx.h"

#include <io.h>
#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include <vector>

#include "Utils.h"
#include "Config.h"
#include "SDServer.h"

static char * cfg_full_path = NULL;

int CfgInitialize(const char * config)
{
	char buf[8192];
	DS_ASSERT(config != NULL);

	cfg_full_path =  strdup(config);
	DS_ASSERT(cfg_full_path != NULL);
	
	if ( SearchFilePath(config, buf, sizeof(buf)) ) {
		free(cfg_full_path);
		cfg_full_path = strdup(buf);
		DS_ASSERT(cfg_full_path != NULL);
	}

	return 0;
}

int GetCfgIniValue(const char * key, DWORD * pValue)
{
	DWORD iniValue;
	DS_ASSERT(pValue != NULL);

	iniValue = *pValue;
	if (cfg_full_path != NULL) {
		return -1;
	}
	
	iniValue = GetPrivateProfileInt("Delivery", key, iniValue, cfg_full_path);
	if (iniValue != *pValue) {
		*pValue = iniValue;	
	}

	return 0;
}

int GetCfgIniString(const char * key, char * buf, size_t len)
{
	if (cfg_full_path == NULL) {
		return 0;
	}

	return GetPrivateProfileString("Delivery", key, buf, buf, len, cfg_full_path);
}
