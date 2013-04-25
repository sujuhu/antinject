#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "antinject.h"

bool notify(const char*inject_dllpath, const char* virus_name)
{
	printf("Found Dll-Inject Attack: %s\n", inject_dllpath);
	printf("Virus Name: %s\n", virus_name);
	printf("The dll is forbidden!\n");

	// 如果返回true， 表示模块被允许加载
	// 如果返回false, 表示模块被拒绝加载
	return false;
}

int main(int argc, char* argv[])
{
	if (!enable_antinject(notify, "db")) {
		printf("Start Anti-inject Failed, RC= %d\n", errno);
		return -1;
	}
	printf("Anti-inject has been launched.\n");

	Sleep(1111111111);
	disable_antinject();
	printf("Anti-inject has stopped\n");
	return 0;
}