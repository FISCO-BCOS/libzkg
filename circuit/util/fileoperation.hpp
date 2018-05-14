/*
 * @file: fileoperation.hpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include <memory>
#include <cstdio>
#include <fstream>
#include <string>

template <typename T>
void saveToFile(const std::string path, T &obj)
{
    //LOCK(cs_ParamsIO);

    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template <typename T>
void loadFromFile(const std::string path, T &objIn)
{
    //LOCK(cs_ParamsIO);
    std::ios::sync_with_stdio(false);

    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if (!fh.is_open())
    {
        throw std::runtime_error(std::string("could not load param file at ") + path);
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    objIn = std::move(obj);

    std::ios::sync_with_stdio(true);
}
