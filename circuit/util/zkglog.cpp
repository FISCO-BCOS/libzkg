/*
 * @file: zkglog.cpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "zkglog.h"
using namespace std;

unsigned zkg_log_verbosity = ZKG_LOG_ALL;

long long get_current_time()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

time_t clock_time;
string get_time(bool isshow)
{
	time_t now = get_current_time();
	string ret;
	if (isshow)
		ret = string("(timestamp: ") + string(to_string(now)) + string(" delta: ") + string(to_string(now - clock_time)) + string(")");
	clock_time = now;
	return ret;
}