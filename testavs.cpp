// testavs.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>

#include "../include/avs_interface.h"
#include "../include/typedef.h"

#include "../include/unrar/dll.hpp"

int g_dwVirusCount  = 0;
int g_dwFileCount   = 0;


//功能：测试一个样本函数
//参数：
//		strFilePath 文件路径
//返回：无
void check_one_file(char *strFilePath)
{
	FILE *fp;
	u32	nFileSize;
	s8 *pFileBuf;

	void *nHandle;
	StreamAvEngineIn saei;
	StreamAvEngineOut saeo;
	int nCheckResult;

	g_dwFileCount++;

	fp = fopen(strFilePath, "rb");
	if(NULL != fp)
	{
		fseek(fp, 0, SEEK_END);
		nFileSize = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		pFileBuf = (s8 *)malloc(nFileSize);
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
						g_dwVirusCount++;
						printf("Found Virus(%d/%d %s)!\n", g_dwVirusCount, g_dwFileCount, saeo.virusInfo.strVirusName);
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
							g_dwVirusCount++;
							printf("Found Virus(%d/%d %s %s)!\n", g_dwVirusCount, g_dwFileCount, saeo.virusInfo.strVirusName, saeo.virusInfo.strVirusType);

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
							if(AV_ENGINE_FIND_NOTHING != nCheckResult && AV_ENGINE_END_THIS_STREAM_CHECK != nCheckResult)
							{
								g_dwVirusCount++;
								printf("Found Virus(%d/%d %s %s)!\n", g_dwVirusCount, g_dwFileCount, saeo.virusInfo.strVirusName, saeo.virusInfo.strVirusType);

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
}


int _tmain(int argc, _TCHAR* argv[])
{
	StreamAvEngineWorkType sewt;
	if(0 == init_stream_av_engine("D:\\yjw\\avs_old\\db"))
	{
		sewt.nUnRar = 1;		//解压包裹
		sewt.nDecodeEmail = 0;  //不解密邮件
		sewt.nUnrarFloor = 2;	//最大支持2层解压缩
		sewt.nUnrarFileSize = 1024*1024;   //对1M以上的文件不解压
		config_stream_av_engine_work_type(&sewt);

		check_one_file("D:\\yjw\\avs_old\\virus\\00712860758916e3f745b682bd673020.EXE");
		check_one_file("c:\\WINDOWS\\system32\\notepad.exe");

		destroy_stream_av_engine();
	}

	return 0;
}

