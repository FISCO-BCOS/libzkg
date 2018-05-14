/*
 * @file: zkglog.h
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef ZKG_LOG_H_
#define ZKG_LOG_H_
#include <iostream>
#include <assert.h>
#include <sys/time.h>
#include <string>
#include <vector>
#include <sstream>

/*
 *  Zkg simple log
 *  Usage:
 *      LOG(INFO) << "this is info" << endl;
 *      LOG(DEBUG) << "this is debug" << endl;
 *      LOG(TRACE) << "this is trace" << endl;
 *      LOG(WARNING) << "this is warning" << endl;
 *      LOG(ERROR) << "this is error" << endl;
 */

long long get_current_time();
std::string get_time(bool isshow = true);

const std::string LOG_HEADER = "[libzkg | ";
extern unsigned zkg_log_verbosity;

#define ZKG_LOG_NONE (0)
#define ZKG_LOG_INFO (0x1 << 0)
#define ZKG_LOG_DEBUG (0x1 << 1)
#define ZKG_LOG_TRACE (0x1 << 2)
#define ZKG_LOG_WARNING (0x1 << 3)
#define ZKG_LOG_ERROR (0x1 << 4)
#define ZKG_LOG_ALL (ZKG_LOG_INFO | ZKG_LOG_DEBUG | ZKG_LOG_TRACE | ZKG_LOG_WARNING | ZKG_LOG_ERROR)

#define LOG_INFO if (zkg_log_verbosity & ZKG_LOG_INFO) std::cout << LOG_HEADER << "INFO" << "]: "  
#define LOG_DEBUG if (zkg_log_verbosity & ZKG_LOG_DEBUG) std::cout << LOG_HEADER << "DEBUG]" << get_time() << ": "  
#define LOG_TRACE if (zkg_log_verbosity & ZKG_LOG_TRACE) std::cout << LOG_HEADER << "TRACE | " << __FUNCTION__ << "]" << get_time() << ": "  
#define LOG_WARNING if (zkg_log_verbosity & ZKG_LOG_WARNING) std::cout << LOG_HEADER << "WARNING | " << __PRETTY_FUNCTION__ << "]" << get_time() << ": "  
#define LOG_ERROR if (zkg_log_verbosity & ZKG_LOG_ERROR) std::cout << LOG_HEADER << "ERROR | " << __PRETTY_FUNCTION__ << "]" << get_time() << ": "  

#define LOG(verbosity) LOG_##verbosity

template <typename T>
void print_vector(std::vector<T> vec)
{
	std::stringstream ss;
	for (auto i : vec)
	{
		ss << i;
	}
	LOG(DEBUG) << ss << std::endl;
}
#endif