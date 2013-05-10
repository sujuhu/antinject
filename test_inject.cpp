#pragma warning(disable:4996)
#include <stdio.h>
#include <direct.h>
#include <stdlib.h>
#include <windows.h>
#include <typedef.h>
#include <inject.h>
#include <procutil.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
void usage()
{
	printf("usage: test_inject.exe <dll>\n");
	printf("example: test_inject.exe test_dll.dll\n");
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		usage();
		return -1;
	}

	const char* test_dll = argv[1];
	if (!PathFileExists(test_dll)) {
		printf("error: %s not exist\n", test_dll);
		return -1;
	}

	// enum all process
	int process_list = process_list_new();
	int count = process_list_count(process_list);
	pid_t pid_target = INVALID_PID;
	for (int i=0; i<count; i++) {
		pid_t pid = process_list_entry(process_list, i);
		if (pid == INVALID_PID)
			continue;

		char procname[512] = {0};
		if (!process_name_by_pid(pid, procname, sizeof(procname)-1)){
			continue;
		}

		if (0 == stricmp(procname, "test_antinject.exe")) {
			pid_target = pid;
			break;
		}
	}
	process_list_delete(process_list);

	if (pid_target == INVALID_PID) {
		printf("Target Process PID: %d\n", pid_target);
		return 0;
	}

	char injectdll_path[MAX_PATH] = {0};
	_getcwd(injectdll_path, MAX_PATH);
	PathAppend(injectdll_path, test_dll);
	if (!inject_dll_to_process(pid_target, injectdll_path)) {
		printf("inject process %d fail\n", pid_target);
	} else {
		printf("inject process %d success\n", pid_target);
	}

	return 0;
}

