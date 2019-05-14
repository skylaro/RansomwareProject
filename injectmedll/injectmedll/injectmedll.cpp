// injectordll.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "injectmedll.h"


// This is an example of an exported variable
INJECTMEDLL_API int ninjectordll=0;

// This is an example of an exported function.
INJECTMEDLL_API int fninjectmedll(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
Cinjectmedll::Cinjectmedll()
{
    return;
}
