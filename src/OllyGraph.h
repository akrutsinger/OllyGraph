#ifndef __OLLYGRAPH_H__
#define __OLLYGRAPH_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "plugin.h"

/*  To use this exported function of dll, include this header
 *  in your project.
 */
#ifdef BUILD_DLL
    #define DLL_EXPORT __declspec(dllexport)
#else
    #define DLL_EXPORT __declspec(dllimport)
#endif

#define PLUGIN_NAME		L"OllyGraph"		/* Unique plugin name */
#define PLUGIN_VERS		L"0.2.0"		/* Plugin version (stable . update . patch  - status) */

#ifdef __cplusplus
extern "C" {
#endif

/* Menu items */
#define MENU_LIST_INTRAMODULE_CALLS		1
#define MENU_LIST_INTERMODULE_CALLS		2
#define MENU_LIST_ALL_CALLS				3
#define	MENU_PROCEDURE_FLOWGRAPH		4
#define MENU_PROCEDURE_CALL_GRAPH		5
#define MENU_XREFS_TO_ADDRESS_GRAPH		6
#define MENU_XREFS_FROM_ADDRESS_GRAPH	7
#define	MENU_SETTINGS					8
#define	MENU_ABOUT						9

/* Global Declarations */


/**
 * Forward declarations
 */
 /* Menu functions */
int menu_handler(t_table *pTable, wchar_t *pName, ulong index, int nMode);
void display_about_message(void);

/* Intramodule call table functions */
int initialize_call_table(void);
int show_call_table(t_table *pt, wchar_t *name, ulong index, int mode);
int draw_call_table(wchar_t *s, uchar *mask, int *select, t_table *pt, t_drawheader *ph, int column, void *cache);

long call_table_func(t_table *pt, HWND hw, UINT msg, WPARAM wp, LPARAM lp);
void find_intramodular_calls(void);

typedef struct t_call_table {
	/* Obligatory header, its layout _must_ coincide with t_sorthdr! */
	ulong		addr;		/* address of the call */
	ulong		size;		/* Size of index, always 1 in our case */
	ulong		type;		/* Type of entry, TY_xxx */
	// Custom data follows header.
	wchar_t		command[TEXTLEN];	/* decoded command text */
	ulong		dest_addr;			/* destination address of call */
	wchar_t		dest_name[TEXTLEN];	/* decoded destination name */
	wchar_t		comment[TEXTLEN];	/* comment that applies to the whole command */
} t_call_table;

#ifdef __cplusplus
}
#endif

#endif	/* __OLLYGRAPH_H__ */
