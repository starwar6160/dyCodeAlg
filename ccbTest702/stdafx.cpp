// stdafx.cpp : 只包括标准包含文件的源文件
// ccbTest702.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"

// TODO: 在 STDAFX.H 中
// 引用任何所需的附加头文件，而不是在此文件中引用
#ifdef _DEBUG
#pragma comment(lib,"gtestd.lib")
#pragma comment(lib,"gtest_main-mdd.lib")
#else
#pragma comment(lib,"gtest.lib")
#pragma comment(lib,"gtest_main-md.lib")
#endif // _DEBUG
#pragma comment(lib,"jclmsCCB2014.lib")
