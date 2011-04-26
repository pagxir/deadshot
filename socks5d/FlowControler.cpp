#include "stdafx.h"
#include <winsock.h>

#include "FlowControler.h"

static LONG UPLOAD_LIMIT = (30960);

CFlowControler::CFlowControler()
:m_flowRate(0), m_ctrlRate(UPLOAD_LIMIT)
{
	m_ctrlTime = GetTickCount() / 500;
}

CFlowControler::~CFlowControler()
{

}

void CFlowControler::Update(size_t count)
{
	time_t now;
    now = GetTickCount() / 500;

	m_flowRate += count;
    while (m_ctrlTime < now)
	{
		if (m_flowRate > m_ctrlRate)
		{
			m_flowRate -= m_ctrlRate;
			m_ctrlRate = 0;
		}
		else
		{
			m_ctrlRate  -= m_flowRate;
			m_ctrlRate >>= 1;
			m_flowRate = 0;
		}
		m_ctrlRate += UPLOAD_LIMIT;
		m_ctrlTime++;
    }
}

BOOL CFlowControler::Waiting()
{
	Update( 0 );
	size_t limit = m_ctrlRate + UPLOAD_LIMIT;
	return (m_flowRate > limit);
}

int SetUploadLimited(size_t upload_limit)
{
	LONG uplimit = upload_limit;
	InterlockedExchange(&UPLOAD_LIMIT, uplimit);
	return 0;
}
