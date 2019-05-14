// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the INJECTORDLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// INJECTORDLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef INJECTMEDLL_EXPORTS
#define INJECTMEDLL_API __declspec(dllexport)
#else
#define INJECTOMEDLL_API __declspec(dllimport)
#endif

// This class is exported from the dll
class INJECTMEDLL_API Cinjectmedll {
public:
	Cinjectmedll(void);
	// TODO: add your methods here.
};

extern INJECTMEDLL_API int ninjectmedll;

INJECTMEDLL_API int fninjectmedll(void);
