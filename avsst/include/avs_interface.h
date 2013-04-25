#ifndef _AVS_INTERFACE_H_
#define _AVS_INTERFACE_H_

#include <time.h>

#define  AVS_API

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

//功能：初始化接口，加载病毒库
//参数：
//		strLibPath 病毒库路径
//返回：初始化成功0,否则返回错误码
AVS_API int init_stream_av_engine(char *strLibPath);


//功能：销毁引擎，释放引擎资源
//参数：无
//返回：无
AVS_API void destroy_stream_av_engine();


typedef struct tagStreamAvEngineWorkType
{
	int nUnRar;				//设置非0值支持解压缩,
	int nDecodeEmail;		//设置非0值支持邮件解密
	int	nUnrarFloor;		//设置解压层数，最大值是2，当bUnRar为非0值的时候本字段有效
	//time_t tUnrarTime;		//设置最大许可解压时间，单位毫秒，当bUnRar为非0值的时候本字段有效
	int	nUnrarFileSize;		//设置压缩包大小最大值(单位：B)
	//int	nMaxMemorySize;		//设置引擎最大许可使用内存（主要是控制引擎缓冲区内存使用），单位兆字节
	char strTempPath[260];		//设置临时目录,程序内部可能会用到(比如解压大文件的时候)(可以不设置,这样默认是当前目录)
}StreamAvEngineWorkType, *PStreamAvEngineWorkType;

//功能：设置引擎工作方式（默认情况是不支持解压缩、邮件解密扫描）
//参数：
//		pStreamAvEngineWorkType 传入的工作方式结构体指针
//返回：无(如需解压包裹,请调用本函数进行相关设置)
AVS_API void config_stream_av_engine_work_type(PStreamAvEngineWorkType pStreamAvEngineWorkType);


//功能：升级病毒库，升级成功后不重启引擎也会使用新库扫描，升级失败则不对现有引擎和库文件造成任何影响。
//参数：
//		strLibPath 病毒库路径
//返回：成功返回0,否则返回错误码
//说明：这个函数内部可能会有阻塞情况
AVS_API int engine_update_virus_lib(char *strLibPath);


//功能：验证病毒库的有效性
//参数：
//		strUpdateLibPath 升级后的病毒库路径
//返回：有效返回0,否则返回错误码
//说明：服务器库包裹就用打包时间判定新旧
AVS_API int check_avs_library_valid(char *strUpdateLibPath);


//功能：查询出错信息
//参数：
//		nErrorCode 错误码
//返回：错误码如果有对应错误信息，返回错误信息字符串指针，否则NULL
AVS_API char *query_engine_error_info(int nErrorCode);


#define STREAM_CHECK_HANDLE 0	//获取流检测句柄标志
#define FILE_CHECK_HANDLE	1	//或者文件检测句柄标志

#define NOT_CHECK_EMAIL		0	//要检测的不是邮件
#define CHECK_EMAIL			1	//检测邮件

#define UNKNOW_STREAM_LEN	0	//不知道流的长度,即在流结束前不知道流有多长
#define KNOW_STREAM_LEN		1	//知道流的长度,在流结束前知道流长/或者整个流结束后再检测病毒(设置此标志)

//功能：获取一个流或者文件检测句柄
//参数：
//		nHandleType 需要获取的句柄类型
//		nCheckEmailType 是否检测邮件
//		nKnowStreamLen 表示当前要检测流或者文件,我们是否有绝对的把握确定它的长度,如果我们能确定它有多少字节,请设置这个标志,可以提高效率
//返回：成功返回句柄值（一定非NULL），失败返回NULL
AVS_API void *av_engine_create_handle(int nHandleType, int nCheckEmailType, int nKnowStreamLen);


//功能：关闭文件或者流检测句柄
//参数：
//		nHandle 句柄值
//返回：成功0，否则-1
AVS_API int av_engine_close_handle(void *nHandle);


//功能：复用文件或者流检测句柄
//参数：
//		nHandle 句柄值
//返回：返回传入句柄
AVS_API void * av_engine_reuse_handle(void *nHandle);


#define FILE_SIGNLE_PACKET_BUF	0	//表示输入的一个单独的数据包
#define FILE_ALL_PACKEt_BUF		1	//表示输入的一个“完整”的文件拼合缓冲区

//文件格式检测传入参数单独结构体
typedef struct tagFileStreamAvEngineIn
{
	int		nAllPacketBuf;		//设置成FILE_SIGNLE_PACKET_BUF或者FILE_ALL_PACKEt_BUF
}FileStreamAvEngineIn, *PFileStreamAvEngineIn;

#define STREAM_END		1	//流结束标志
#define STREAM_NOT_END	0	//流未结束标志

//这个结构体完全由调用者填充
typedef struct tagStreamAvEngineIn
{
	char *pData;		//数据指针(本字段严禁设置为NULL)
	int nDataLen;		//数据长度(如果本次检测只为了告知引擎流结束,并无实际数据传入,这个字段务必设置成0)
	int	nEnd;			//表示流是否结束,STREAM_END表示结束,否则设置成STREAM_NOT_END
	
	FileStreamAvEngineIn	fin;	//文件格式检测病毒时候,自己独有的结构
}StreamAvEngineIn, *PStreamAvEngineIn;

#define AV_ENGINE_FIND_NOTHING			(0)
#define AV_ENGINE_END_THIS_STREAM_CHECK	(1)
#define AV_ENGINE_FIND_VIRUS			(2)

//检测到的病毒信息
typedef struct tagCheckedVirusInfo
{
	//下面两个字段引擎内部设置,理论上不会为NULL,但是最好在使用前判断下是否为NULL
	char *	strVirusName;	//返回病毒名
	char *	strVirusType;	//返回病毒类型
}CheckedVirusInfo, *PCheckedVirusInfo;

//检测到病毒,返回具体信息定义
typedef struct tagStreamAvEngineOut
{
	//只有当返回AV_ENGINE_FIND_VIRUS时才有效
	CheckedVirusInfo	virusInfo;	//检测到的病毒信息

	int		nNeedAllPacket;	//是否需要缓冲所有包,非0表示需要所有包数据,调用file_av_engine_check_virus函数时候用到,一般是对一些rar包裹,需要全文件才能有效解压缩,这个值每次调用file_av_engine_check_virus都会设置
}StreamAvEngineOut, *PStreamAvEngineOut;

//功能：流格式检测病毒（本函数支持多个线程同时调用）
//参数：
//		pStreamAvEngineIn 检测传入的结构体指针
//		nHandle 流句柄
//		pStreamAvEngineOut 检测到病毒返回病毒详细信息(如果不需要这个信息可以传入NULL)
//返回：END_THIS_STREAM_CHECK表示对当前流不需要检测了，但未检测到病毒；检测到病毒返回AV_ENGINE_FIND_VIRUS；未检测到病毒返回AV_ENGINE_FIND_NOTHING
//说明：返回AV_ENGINE_END_THIS_STREAM_CHECK/AV_ENGINE_FIND_VIRUS时,就不应该再调用本函数检测本流了
AVS_API int stream_av_engine_check_virus(PStreamAvEngineIn pStreamAvEngineIn, void *nHandle, PStreamAvEngineOut pStreamAvEngineOut);


//功能：文件格式检测病毒（本函数支持多个线程同时调用）
//参数：
//		pStreamAvEngineFileFormatIn 检测传入的结构体指针
//		nFileHandle 文件相关信息句柄
//		pStreamAvEngineOut 检测到病毒返回病毒详细信息(如果不需要这个信息可以传入NULL)
//返回：END_THIS_STREAM_CHECK表示对当前流不需要检测了，但未检测到病毒；检测到病毒返回AV_ENGINE_FIND_VIRUS；未检测到病毒返回AV_ENGINE_FIND_NOTHING
//说明：返回AV_ENGINE_END_THIS_STREAM_CHECK/AV_ENGINE_FIND_VIRUS时,就不应该再调用本函数检测本文件了
AVS_API int file_av_engine_check_virus(PStreamAvEngineIn pStreamAvEngineIn, void *nHandle, PStreamAvEngineOut pStreamAvEngineOut);


#ifdef __cplusplus
};
#endif //__cplusplus

#endif //_AVS_INTERFACE_H_
