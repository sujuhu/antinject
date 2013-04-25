#ifndef _TYPE_DEF_H_
#define _TYPE_DEF_H_

#define u8		unsigned char
#define s8		char

#define u16		unsigned short
#define s16		short

#define u32		unsigned int
#define s32		int

#ifndef WINDOWS
#define u64		unsigned int64
#define s64		int64
#else //WINDOWS
#define u64		unsigned __int64
#define s64		__int64
#endif //WINDOWS

#ifndef MAX_PATH
#define MAX_PATH 260
#endif //MAX_PATH

#ifdef WINDOWS
#define mktemp _mktemp
#define mkdir _mkdir
#else //WINDOWS
//#define mktemp mkstemp
#endif //WINDOWS

#endif //_TYPE_DEF_H_
