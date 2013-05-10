#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <detours.h>
#include <typedef.h>
#include <avs_interface.h>
#include "antinject.h"

#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

typedef LONG NTSTATUS, *PNTSTATUS;
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef 
NTSTATUS 
(NTAPI *LdrLoadDll)(
 	IN PWCHAR		pszSearchPath OPTIONAL,
 	IN PULONG		puDllCharacteristics OPTIONAL,
	IN PUNICODE_STRING pusDllName,
	OUT PHANDLE        phDllHandle);

LdrLoadDll OriLdrLoadDll = NULL;
antinject_notify g_notify = NULL;



//功能：测试一个样本函数
//参数：
//		strFilePath 文件路径
//返回：无
void check_one_file(char *strFilePath, 
	char* virus_name, 
	size_t name_max_len)
{
	FILE *fp;
	uint32_t	nFileSize;
	char *pFileBuf;

	void *nHandle;
	StreamAvEngineIn saei;
	StreamAvEngineOut saeo;
	int nCheckResult;

	fp = fopen(strFilePath, "rb");
	if(NULL == fp) {
		return;
	}

	fseek(fp, 0, SEEK_END);
	nFileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pFileBuf = (char *)malloc(nFileSize);
	if(NULL != pFileBuf)
	{
		if(nFileSize == fread(pFileBuf, 1, nFileSize, fp))
		{
			int nI;

			//打开一个检测句柄
			nHandle = av_engine_create_handle(FILE_CHECK_HANDLE, NOT_CHECK_EMAIL, UNKNOW_STREAM_LEN);
			if(NULL != nHandle)
			{
				saei.nEnd = STREAM_END;
				saei.nDataLen = nFileSize;
				saei.pData = pFileBuf;
				saei.fin.nAllPacketBuf = FILE_ALL_PACKEt_BUF;

				nCheckResult = file_av_engine_check_virus(&saei, nHandle, &saeo);
				if(AV_ENGINE_FIND_VIRUS == nCheckResult)
				{
					strncpy(virus_name, saeo.virusInfo.strVirusName, name_max_len-1);
				}
				av_engine_close_handle(nHandle);
			}

			//打开一个检测句柄
			nHandle = av_engine_create_handle(FILE_CHECK_HANDLE, NOT_CHECK_EMAIL, UNKNOW_STREAM_LEN);
			if(NULL != nHandle)
			{
				saei.pData = pFileBuf;
				saei.fin.nAllPacketBuf = FILE_ALL_PACKEt_BUF;

				nI = nFileSize > 512 ? 512 : nFileSize;
				for(; nI <= nFileSize; )
				{
					saei.nDataLen = nI;
					if(nFileSize == nI)
					{
						saei.nEnd = STREAM_END;
					}
					else
					{
						saei.nEnd = STREAM_NOT_END;
					}

					nCheckResult = file_av_engine_check_virus(&saei, nHandle, &saeo);
					if(AV_ENGINE_FIND_NOTHING != nCheckResult && AV_ENGINE_END_THIS_STREAM_CHECK != nCheckResult)
					{
						// printf("Found Virus(%d/%d %s %s)!\n", 
						// 		g_dwVirusCount, 
						// 		g_dwFileCount, 
						// 		saeo.virusInfo.strVirusName, 
						// 		saeo.virusInfo.strVirusType);
						strncpy(virus_name, saeo.virusInfo.strVirusName, name_max_len-1);
						break;
					}

					if(STREAM_END == saei.nEnd) break;
					nI += 512;
					if(nI > nFileSize) nI = nFileSize;
				}
				av_engine_close_handle(nHandle);
			}

			//打开一个检测句柄
			nHandle = av_engine_create_handle(FILE_CHECK_HANDLE, NOT_CHECK_EMAIL, UNKNOW_STREAM_LEN);
			if(NULL != nHandle)
			{
				saei.fin.nAllPacketBuf = FILE_SIGNLE_PACKET_BUF;

				if(nFileSize >= 512)
				{
					int nOldnI = 0;
					for(nI = 512; nI <= nFileSize; )
					{
						saei.pData = pFileBuf + nOldnI;
						saei.nDataLen = nI - nOldnI;
						if(nFileSize == nI)
						{
							saei.nEnd = STREAM_END;
						}
						else
						{
							saei.nEnd = STREAM_NOT_END;
						}

						nCheckResult = file_av_engine_check_virus(&saei, nHandle, &saeo);
						if (AV_ENGINE_FIND_NOTHING != nCheckResult && 
							AV_ENGINE_END_THIS_STREAM_CHECK != nCheckResult)
						{
							// g_dwVirusCount++;
							// printf("Found Virus(%d/%d %s %s)!\n", 
							// 		g_dwVirusCount, 
							//  	g_dwFileCount, 
							// 		saeo.virusInfo.strVirusName, 
							// 		saeo.virusInfo.strVirusType);
							strncpy(virus_name, saeo.virusInfo.strVirusName, name_max_len-1);

							break;
						}

						if(STREAM_END == saei.nEnd) break;
						nOldnI = nI;
						nI += 512;
						if(nI > nFileSize)
						{
							nI = nFileSize;
						}
					}
				}
				av_engine_close_handle(nHandle);
			}
		}

		free(pFileBuf);
	}

	fclose(fp);
}


NTSTATUS NTAPI SecurityLdrLoadDll(
 	IN PWCHAR		pszSearchPath OPTIONAL,
 	IN PULONG		puDllCharacteristics OPTIONAL,
	IN PUNICODE_STRING pusDllName,
	OUT PHANDLE        phDllHandle)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
 
	do {

		char dllname[512] = {0};
 		wcstombs(dllname, pusDllName->Buffer, pusDllName->Length);

 		//进行病毒扫描	
 		char virus_name[256] = {0};
		check_one_file(dllname, virus_name, sizeof(virus_name));

		// 通知上层逻辑， 让逻辑层来决定是否加载该DLL
		bool is_malware = (strlen(virus_name) > 0 );
 		if (!g_notify(dllname, is_malware)) {
 			// 拒绝运行
 			break;
 		} else {
 			// 允许运行
			Status=OriLdrLoadDll(pszSearchPath,
				puDllCharacteristics,pusDllName,phDllHandle);
 		}
 
	} while (false);
 
	return Status;
}

bool enable_antinject(
	antinject_notify notify_routine, 
	const char* virus_db_fullpath)
{
	HMODULE ntdll = LoadLibrary("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	OriLdrLoadDll = (LdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
	if (OriLdrLoadDll == NULL) {
		return false;
	}

	// 初始化病毒库
	if (0 != init_stream_av_engine((char*)virus_db_fullpath)) {
		// 初始化病毒库失败
		return false;
	}

	// 配置病毒库
	StreamAvEngineWorkType sewt;
	sewt.nUnRar = 0;		//解压包裹
	sewt.nDecodeEmail = 0;  //不解密邮件
	sewt.nUnrarFloor = 1;	//最大支持2层解压缩
	sewt.nUnrarFileSize = 1024*1024;   //对1M以上的文件不解压
	config_stream_av_engine_work_type(&sewt);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OriLdrLoadDll, SecurityLdrLoadDll);
	DetourTransactionCommit();

	g_notify = notify_routine;
	return true;
}

void disable_antinject()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)OriLdrLoadDll, SecurityLdrLoadDll);
	DetourTransactionCommit();

	destroy_stream_av_engine();
}