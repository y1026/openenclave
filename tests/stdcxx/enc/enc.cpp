#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <map>
#include <openenclave.h>
#include "../args.h"

#define BROKEN

using namespace std;

static string _str;

class X
{
public:
    X() : _x(0)
    {
    }
    
    virtual ~X()
    {
    }

    virtual void foo()
    {
    }

private:
    int _x;
};

class Y : public X
{
public:

    Y() : X() 
    {
    }

    virtual ~Y()
    {
    }

    virtual void foo()
    {
    }
};

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;

    if (!args)
        return;

    /* Try strings */
    {
        string s = "hello world";
        s.find("world");
    }

    /* Try vectors */
    {
        vector<string> v;
        v.push_back("red");
        v.push_back("green");
        v.push_back("blue");

        if (v.size() != 3 || v[2] != "blue")
        {
            args->ret = -1;
            return;
        }

        v.clear();
    }

    /* Try maps */
    {
        map<string,int> m;
        m["red"] = 0;
        m["green"] = 1;
        m["blue"] = 2;

        if (m["blue"] != 2)
        {
            args->ret = -1;
            return;
        }
    }

    /* Try new/delete */
    {
        char* p = new char[12];

        if (!p)
        {
            args->ret = -1;
            return;
        }

        strcpy(p, "hello");

        if (strcmp(p, "hello") != 0)
        {
            args->ret = -1;
            return;
        }

        delete [] p;
    }

    /* Test virtual destructors */
    {
        X* x = new Y;

        delete x;
    }

    /* Test stringstream */
    {
        stringstream os;
        os << "hello";

        string s;
        os >> s;

        assert(s == "hello");
    }

    /* Test exceptions */
    {
        struct E { };

        try
        {
            args->caught = false;
            throw E();
        }
        catch (const E& e)
        {
            args->caught = true;
        }
    }

    /* Test RTTI */
    {
        args->dynamicCastWorks = false;

        X* x = new Y;

        Y* y = dynamic_cast<Y*>(x);

        if (y)
            args->dynamicCastWorks = true;
    }

    args->ret = 0;
}