#ifndef ANTI_INJECT_HEADER_
#define ANTI_INJECT_HEADER_

#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*antinject_notify)(
	const char*inject_dllpath, 
	const bool is_malware);

/*
 	启动防注入安全机制
 	notify_routine:  发现注入行为时的通知回调函数
 	virus_db_fullpath: 病毒库全路径

 	return:
 	true:  启动成功
 	false: 启动失败
 */
bool enable_antinject(
	antinject_notify notify_routine, 
	const char* virus_db_fullpath);

/*
	关闭防注入安全机制
 */
void disable_antinject();

#ifdef __cplusplus
};
#endif

#endif