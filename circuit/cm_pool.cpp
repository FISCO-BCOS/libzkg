/*
 * @file: cm_pool.cpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "cm_pool.hpp"
#include "zkg.hpp"
#include "util/zkglog.h"
#include <string>

using namespace std;

void CMPool::set(index_t i, const std::string &cm)
{
    pool[i] = cm;
    index[cm] = i;
}

void CMPool::append(const std::string &cm)
{
    pool.push_back(cm);
    index[cm] = pool.size() - 1;
}

size_t CMPool::size() { return pool.size(); }

CMPool::index_t CMPool::get_index(const std::string &cm)
{
    CMPool::index_mp_it_t it = index.find(cm);

    if (index.end() == it)
    {
        LOG(WARNING) << "cm not found: " << cm << std::endl;
        return -1;
    }

    return it->second;
}

void CMPool::for_each_cm_range(index_t from, index_t to, std::function<void(std::string)> f)
{
    //[from, to]
    //assert(from <= to)
    if( from < 0 || from >= (index_t)pool.size() ||
        to < 0 || to >= (index_t)pool.size())
        throw CMPoolRangeException();

    for (; from <= to; from++)
        f(pool[from]);
}


std::shared_ptr<CMPool> gen_test_cm_containing_pool(string cm_in)
{
    CMPool pool;

    pool.append(Tx1To1API::ZERO_CM());
    for (int i = 0; i < 2; i++)
    {
        string cm_str = string("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af600") + to_string(i);

        pool.append(cm_str);
    }

    pool.append(cm_in);

    for (int i = 2; i < 5; i++)
    {
        string cm_str = string("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af600") + to_string(i);

        pool.append(cm_str);
    }

    LOG(DEBUG) << "-----pool-----" << endl;
    std::string cm_x = cm_in;
    CMPool::index_t cm_idx = pool.get_index(cm_x);
    pool.for_each_cm_range(0, cm_idx,
                           [&](std::string cm) {
                               LOG(DEBUG) << cm << endl;
                           });

    LOG(DEBUG) << "-----pool_rest-----" << endl;
    pool.for_each_cm_range(cm_idx + 1, pool.size() - 1,
                           [&](std::string cm) {
                               LOG(DEBUG) << cm << endl;
                           });

    return make_shared<CMPool>(pool);
}

std::shared_ptr<CMPool> gen_test_cms_containing_pool(std::vector<std::string> cms_in)
{
    assert(cms_in.size() > 0);
    CMPool pool;

    pool.append(Tx1To1API::ZERO_CM());
    for (int i = 0; i < 3; i++)
    {
        string cm_str = string("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af600") + to_string(i);

        pool.append(cm_str);
    }

    for (auto cm_in : cms_in)
        pool.append(cm_in);

    for (int i = 3; i < 5; i++)
    {
        string cm_str = string("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af600") + to_string(i);

        pool.append(cm_str);
    }

    LOG(DEBUG) << "-----pool-----" << endl;
    std::string cm_x = cms_in.back();
    CMPool::index_t cm_idx = pool.get_index(cm_x);
    pool.for_each_cm_range(0, cm_idx,
                           [&](std::string cm) {
                               LOG(DEBUG) << cm << endl;
                           });

    LOG(DEBUG) << "-----pool_rest-----" << endl;
    pool.for_each_cm_range(cm_idx + 1, pool.size() - 1,
                           [&](std::string cm) {
                               LOG(DEBUG) << cm << endl;
                           });

    return make_shared<CMPool>(pool);
}
