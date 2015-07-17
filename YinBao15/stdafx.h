// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             //  从 Windows 头文件中排除极少使用的信息
// Windows 头文件:
#include <windows.h>
#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
using std::cout;
using std::endl;
using std::string;
using std::stringstream;
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp> 
using boost::lexical_cast;
using boost::bad_lexical_cast;
using boost::shared_ptr;
// TODO: 在此处引用程序需要的其他头文件
