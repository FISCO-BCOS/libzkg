/*
 * @file: cm_pool.hpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef CM_POOL_H_
#define CM_POOL_H_
#include <iostream>
#include <memory>
#include <functional>
#include <vector>
#include <string>
#include <map>
#include <assert.h>
#include "zkgexception.hpp"

class CMPool
{
  public:
    typedef int32_t index_t;
    typedef std::map<std::string, index_t> index_mp_t;
    typedef index_mp_t::iterator index_mp_it_t;

    std::vector<std::string> pool;
    index_mp_t index; //根据cm查找它的在pool中是第几个

    CMPool() {}
    virtual ~CMPool() {}

    void set(index_t i, const std::string &cm);
    void append(const std::string &cm);
    size_t size();
    index_t get_index(const std::string &cm);
    void for_each_cm_range(index_t from, index_t to, std::function<void(std::string)> f);
};

std::shared_ptr<CMPool> gen_test_cm_containing_pool(std::string cm_256);
std::shared_ptr<CMPool> gen_test_cms_containing_pool(std::vector<std::string> cms_256);

#endif