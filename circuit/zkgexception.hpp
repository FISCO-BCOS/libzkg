/*
 * @file: zkgexception.hpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef ZKG_EXCEPTION_H_
#define ZKG_EXCEPTION_H_
#include <iostream>
#include <exception>
#include <string>

//CMPool
struct CMPoolRangeException : public std::exception
{
    const char *what() const throw()
    {
        return "CMPool range exception";
    }
};

struct CMNotFoundException : public std::exception
{
    const char *what() const throw()
    {
        return "CM not found in CM pool. Please check secret_key(ask), spend_key(r) and value(v) correct";
    }
};

//Tx1To1
struct ProveParamsLengthException : public std::exception
{
    const char *what() const throw()
    {
        return "Prove params length exception";
    }
};

struct ProveNotSatisfiedException : public std::exception
{
    const char *what() const throw()
    {
        return "Prove params is not satisfied";
    }
};

struct ProveValueException : public std::exception
{
    const char *what() const throw()
    {
        return "Prove value incorrect";
    }
};

struct GovGeneratorException : public std::exception
{
    const char *what() const throw()
    {
        return "Prove overseer's generator(g) is invalid";
    }
};

//Verify
struct VerifyParamsLengthException : public std::exception
{
    const char *what() const throw()
    {
        return "Verify params length exception";
    }
};

struct VerifyParamsValueException : public std::exception
{
    const char *what() const throw()
    {
        return "Verify params value exception";
    }
};

struct ProofLengthException : public std::exception
{
    const char *what() const throw()
    {
        return "Proof length exception";
    }
};

struct GDataLengthException : public std::exception
{
    const char *what() const throw()
    {
        return "G_data length exception";
    }
};

//format exception
struct NotUint256Exception : public std::exception
{
    std::string name;
    NotUint256Exception(const std::string &name): name(name) {}
    const char *what() const throw() override
    {
        std::string info =  name + std::string(" is not uint256 hex format");
        return info.c_str();
    }
};

struct NotBase64StringException : public std::exception
{
    const char *what() const throw()
    {
        return "Param is not base64 string exception";
    }
};

//File exception
struct FileNotFoundException : public std::exception
{
    std::string name;
    FileNotFoundException(const std::string &name) : name(name) {}
    const char *what() const throw() override
    {
        std::string info = name + std::string(" not found");
        return info.c_str();
    }
};

#endif