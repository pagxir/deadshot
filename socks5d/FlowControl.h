#ifndef _FLOWCONTROL_H_
#define _FLOWCONTROL_H_

#include "Network.h"

typedef struct FlowCtrlIdle_Item {
	struct FlowCtrlIdle_Item * next;
	struct FlowCtrlIdle_Item ** prev;
	DWORD magic;
	DWORD state;
	LPVOID context;
	ASYNCCALL * callback;
} FlowCtrlCallback;

BOOL FlowCtrlIsIdle(void);
void FlowCtrlAddflow(size_t iocount);

void FlowCtrlIdle_Init(FlowCtrlCallback * fcb);
void FlowCtrlIdle_Drop(FlowCtrlCallback * fcb);
void FlowCtrlIdle_Delete(FlowCtrlCallback * fcb);
void FlowCtrlIdle_Reset(FlowCtrlCallback * fcb, ASYNCCALL * callback, LPVOID context);

#endif
