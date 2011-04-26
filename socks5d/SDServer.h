#ifndef _SDSERVER_H_
#define _SDSERVER_H_
#include <string>

#define DSPLUGIN_EXPORT extern "C" __declspec( dllexport )
#define MUTEX_NAME ("Global\\EPol_SDServer.Mutex")

struct TaskIdent {
public:
	TaskIdent(const char * id = "");
	TaskIdent(const std::string id);

	operator const char * (void) const;
	friend bool operator < (const TaskIdent & _X, const TaskIdent& _Y);

private:
	std::string idvalue;
};

bool operator < (const TaskIdent & _X, const TaskIdent& _Y);

typedef struct _DSClientPlugin {
	int (* initialize)(void);
	int (* clean)(void);
	int (* start)(void);
	int (* stop)(void);
} DSClientPlugin, * PDSClientPlugin;

int GetFirstTask(TaskIdent & task);
int GetNextTask(const TaskIdent & taskCur, TaskIdent & taskNext);
HANDLE GetTaskProcess(const TaskIdent & task);
int CloseTaskProcess(const TaskIdent & task);
BOOL MakeParentFolder(const char *path);

BOOL IsTaskUserPrompted(const TaskIdent & task);
BOOL IsTaskDone(const TaskIdent & task);
BOOL IsTaskNeeded(const TaskIdent & task);
BOOL IsSetupStarted(const TaskIdent & task);
BOOL IsSetupDettached(const TaskIdent & task);
BOOL IsSetupFinish(const TaskIdent & task);
BOOL IsSetupCheckResult(const TaskIdent & task);

int FormatPathSlash(std::string & source);

int Delivery(HANDLE hEvent, const char * RequestName, size_t len);
size_t GetTaskCachePath(const TaskIdent & ident, char * folder, size_t len);

#define DS_WARN(exp)
#define DS_ERROR(exp)
#define DS_ASSERT(exp) ((exp) || ds_abort("DS_ASSERT", #exp, __FILE__, __LINE__))
int ds_abort(const char * msg, const char * exp, const char * file, int line);

#endif
