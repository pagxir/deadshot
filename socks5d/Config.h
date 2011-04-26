#ifndef __CONFIG_H__
#define __CONFIG_H__

#pragma once
#include <string>

#define SZSERVICENAME "SDServer"

DWORD GetCenterAddress(void);
void UpdateSqlServerConfig(const char * uid, const char * pwd, const char * constr);

int CfgInitialize(const char * config);
int GetCfgIniValue(const char * key, DWORD * pValue);
int GetCfgIniString(const char * key, char * buf, size_t len);

#endif
