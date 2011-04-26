#include "stdafx.h"
#include <stdio.h>
#include <string.h>

#include "FlowMeasure.h"

CFlowMeasure::CFlowMeasure(size_t span)
:m_span(span), m_flowRate(0), m_lastUpdate(0), m_currRate(0),m_lastPrint(0)
{
	time(&m_lastPrint);
	time(&m_lastUpdate);
	memset(m_buckets, 0, sizeof(m_buckets));
}

CFlowMeasure::~CFlowMeasure()
{
	
}

void CFlowMeasure::AddTransfer(size_t count)
{
	time_t now;
	
    time(&now);
    size_t index = (now % m_span);
    if (m_buckets[index].tTime != now)
	{
		m_buckets[index].nTransfer = 0;
		m_buckets[index].tTime = now;
    }
    m_buckets[index].nTransfer += count;
	
    while (m_lastUpdate < now)
	{
		m_flowRate >>= 1;
		m_currRate = m_flowRate;
		m_lastUpdate ++;
    }
    m_flowRate += count;
}

size_t CFlowMeasure::GetAverageRate(void)
{
	time_t tmNow;
	size_t total = 0;
    time_t lastTime = time(&tmNow);

    for (int i = 0; i < (int)m_span; i ++)
	{
		if (m_buckets[i].tTime + (long)m_span >= tmNow &&
			m_buckets[i].tTime < tmNow)
		{
			total += m_buckets[i].nTransfer;
			if (lastTime > m_buckets[i].tTime)
				lastTime = m_buckets[i].tTime;
		}
    }

	return (lastTime < tmNow)? total / (tmNow - lastTime): 0;
}

void CFlowMeasure::PrintStatus()
{
	time_t tmNow;
	
    if (m_lastPrint != time(&tmNow))
	{
		fprintf(stderr, "Average: %6d B/s Current: %6d B/s\n",
			GetAverageRate(), m_currRate);
		m_lastPrint = tmNow;
	}

	return;
}
