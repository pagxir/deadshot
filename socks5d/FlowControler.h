#ifndef __FLOWCONTROL_H__
#define __FLOWCONTROL_H__

#include <time.h>

#pragma once

class CFlowControler  
{
public:
	BOOL Waiting();
	void Update(size_t count);

public:
	CFlowControler( );
	virtual ~CFlowControler();

private:
	time_t m_ctrlTime;
	size_t m_ctrlRate;
	size_t m_flowRate;
};

int SetDownloadLimit(size_t limit);

#endif
