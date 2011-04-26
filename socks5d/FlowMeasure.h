#ifndef __FLOWMEASURE_H__
#define __FLOWMEASURE_H__

#pragma once
#include <time.h>

#define MAX_SPAN 10

struct FlowMeasureBucket
{
	time_t tTime;
	size_t nTransfer;
};

class CFlowMeasure  
{
public:
	CFlowMeasure(size_t span);
	virtual ~CFlowMeasure();

public:
	void PrintStatus(void);
	void AddTransfer(size_t count);

private:
	size_t m_span;
	size_t GetAverageRate();
	FlowMeasureBucket m_buckets[MAX_SPAN];

private:
	size_t m_flowRate;
	time_t m_lastUpdate;
	
private:
	size_t m_currRate;
	time_t m_lastPrint;
};

#endif

