#include "Stdafx.h"
#include <assert.h>
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>

#include "Utils.h"
#include "Config.h"
#include "Network.h"
#include "SDServer.h"
#include "FlowControl.h"
#include "FlowControler.h"

#define LIST_NAME(xx) FlowCtrlIdle_##xx
#define LIST_SCOPE extern
#include "DLinkedList_c.h"
#undef LIST_SCOPE
#undef LIST_NAME

typedef struct _PluginParam {
	BOOL quited;
	AIOCB callout;
} PluginParam, * PPluginParam;

static Callout callout;
static AIOCB stopcall;
static AIOCB startcall;

static PluginParam FlowControl;
static void FlowControlCallback(LPVOID lpVoid);
static CFlowControler flow_controler;

BOOL FlowCtrlIsIdle(void)
{
	int test = !flow_controler.Waiting();
	return test;
}

void FlowCtrlAddflow(size_t count)
{
	flow_controler.Update(count);
	return;
}

void FlowCtrlIdle_Reset(FlowCtrlCallback * fcb, ASYNCCALL * callback, LPVOID context)
{
	fcb->callback = callback;
	fcb->context = context;
	FlowCtrlIdle_Insert(fcb);
}

static void StartStopCall(LPVOID status)
{
	switch((BOOL)status) {
		case TRUE:
			FlowControl.quited = TRUE;
			CalloutStop(&callout);
			break;

		case FALSE:
			if (!FlowControl.quited)
				CalloutReset(&callout, FlowControlCallback, NULL, 1000);
			break;

		default:
			break;
	}
}

static int FlowControlStart(void)
{
	PushAsyncCall(&startcall);
	return 0;
}

static int FlowControlStop(void)
{
	PushAsyncCall(&stopcall);
	return 0;
}

static int FlowControlInit(void)
{
	CalloutInit(&callout);
	AIOCB_Init(&stopcall, StartStopCall, (PVOID)TRUE);
	AIOCB_Init(&startcall, StartStopCall, (PVOID)FALSE);
	FlowControl.quited = FALSE;
	return 0;
}

static int FlowControlClean(void)
{
	CalloutDrop(&callout);
	return 0;
}

static void FlowControlCallback(LPVOID lpVoid)
{
	FlowCtrlCallback * fcb;

	FlowCtrlAddflow(0);

	if (!FlowControl.quited) {
		DWORD timeo = 2000;
		fcb = FlowCtrlIdle_Header();
		if (!FlowCtrlIdle_Empty())
			timeo = 500;
		CalloutReset(&callout, FlowControlCallback, NULL, timeo);
	}

	while (FlowCtrlIsIdle() && !FlowCtrlIdle_Empty()) {
		fcb = FlowCtrlIdle_Header();
		FlowCtrlIdle_Delete(fcb);
		fcb->callback(fcb->context);
	}
}

DSPLUGIN_EXPORT int DSGetPlugin_FlowControl(PDSClientPlugin pplugin)
{
	pplugin->initialize = FlowControlInit;
	pplugin->clean = FlowControlClean;

	pplugin->start = FlowControlStart;
	pplugin->stop = FlowControlStop;
	return 0;
}
