/*******************************************************************************
 * OllyGraph - OllyGraph.c
 *
 * Copyright (c) 2013, Austyn Krutsinger
 * All rights reserved.
 *
 * OllyGraph is free (as in "free beer")
 *
 ******************************************************************************/

/*******************************************************************************
 * Things to change as I think of them...
 * [ ] = To do
 * [?] = Might be a good idea?
 * [!] = Implemented
 * [+] = Added
 * [-] = Removed
 * [*] = Changed
 * [~] = Almost there...
 *
 *
 * Version 0.2.0
 * [*] Complete code rewrite. Much cleaner and faster.
 * [*] Change project to Code::Blocks from Visual Studio
 * [*] Fixed bug where last command of procedure wasn't shown in the last node
 * [*] minor formatting to the way the commands in the nodes are displayed
 * [+] Unlimited number of nodes/edges can be analyzed
 * [+] List intramodular calls
 * [+] Implemented primitive memory leak detection for debugging
 * [+] Save wingraph32.exe as a resource in plugin and execute resource if wingraph cannot be found - Thanks Jan!
 * [+] Implemented call graph for a procedure
 * [+] Added call graph highlighting
 * [-] Removed global variable for nodes list.
 *
 * Version 0.1.0 (17MAR2013)
 * [+] Initial release
 *
 *
 * -----------------------------------------------------------------------------
 * TODO
 * -----------------------------------------------------------------------------
 *
 * [*] Fix crash when call generate call graph on procedure that has been modified
 * [+] Change VCG parameters from Settings dialog
 * [*] Make call graph display names of functions if known (exempli gratia User32.SetWindowTextA)
 * [*] In list intra-modular calls, don't list calls that call a jmp where the jmp is to an external module
 *
 ******************************************************************************/

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "OllyGraph.h"
#include "settings.h"
#include "resource.h"
#include "plugin.h"
#include "GraphProcedures.h"

#ifdef FIND_MEMORY_LEAKS
#include "MemCheck.h"
#endif /* FIND_MEMORY_LEAKS */

/* Global variables */
extern HINSTANCE plugin_instance;

/* Module specific globals */
static t_table	call_table;		/* call table used for 'inter' and 'intra' calls */

/*
 * Plugin menu that will appear in the main OllyDbg menu
 * and in popup menu.
 */
static t_menu ollygraph_menu[] = {
	{
		L"List Intramodule Calls",
		L"List Intramodule Calls",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'L', menu_handler, NULL, MENU_LIST_INTRAMODULE_CALLS
	},
	{
		L"|Generate Procedure Flow Graph",
		L"Generate Procedure Flow Graph",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'F', menu_handler, NULL, MENU_PROCEDURE_FLOWGRAPH
	},
	{
		L"Generate Procedure Call Graph",
		L"Generate Procedure Call Graph",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'C', menu_handler, NULL, MENU_PROCEDURE_CALL_GRAPH
	},
	//{ L"Generate XRefs To Address Graph",
	//	L"Generate XRefs To Address Graph",
	//	KK_DIRECT|KK_CTRL|KK_SHIFT|'X', menu_handler, NULL, MENU_XREFS_TO_ADDRESS_GRAPH },
	//{ L"Generate XRefs From Address Graph",
	//	L"Generate XRefs From Address Graph",
	//	KK_DIRECT|KK_CTRL|KK_SHIFT|'A', menu_handler, NULL, MENU_XREFS_FROM_ADDRESS_GRAPH },
	{
		L"|Settings",
		L"Configure Path to Wingraph32",
		K_NONE, menu_handler, NULL, MENU_SETTINGS
	},
	{
		L"|About",
		L"About OllyGraph",
		K_NONE, menu_handler, NULL, MENU_ABOUT
	},
	/* End of menu. */
	{ NULL, NULL, K_NONE, NULL, NULL, 0 }
};

/*
 * Plugin menu that will appear in the popup menu.
 */
static t_menu ollygraph_popup_menu[] = {
	{
		L"List Intramodule Calls",
		L"List Intramodule Calls",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'L', menu_handler, NULL, MENU_LIST_INTRAMODULE_CALLS
	},
	{
		L"|Generate Procedure Flow Graph",
		L"Generate Procedure Flow Graph",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'F', menu_handler, NULL, MENU_PROCEDURE_FLOWGRAPH
	},
	{
		L"Generate Procedure Call Graph",
		L"Generate Procedure Call Graph",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'C', menu_handler, NULL, MENU_PROCEDURE_CALL_GRAPH
	},
	//{ L"Generate XRefs To Address Graph",
	//	L"Generate XRefs To Address Graph",
	//	KK_DIRECT|KK_CTRL|KK_SHIFT|'X', menu_handler, NULL, MENU_XREFS_TO_ADDRESS_GRAPH },
	{
		L"|Settings",
		L"Configure Path to Wingraph32",
		K_NONE, menu_handler, NULL, MENU_SETTINGS
	},
	/* End of menu. */
	{ NULL, NULL, K_NONE, NULL, NULL, 0 }
};

/*
 *
 * Plugin specific functions
 *
 */
/**
 * @display_about_message
 *
 *		Displays "About" message box
 */
void display_about_message(void)
{
	wchar_t about_message[TEXTLEN] = { 0 };
	wchar_t buf[SHORTNAME];
	int n;

	/* Debuggee should continue execution while message box is displayed. */
	Resumeallthreads();
	n = StrcopyW(about_message, TEXTLEN, L"OllyGraph v");
	n += StrcopyW(about_message + n, TEXTLEN - n, PLUGIN_VERS);
	n += StrcopyW(about_message + n, TEXTLEN - n, L"\n\nCoded by Austyn Krutsinger <akrutsinger@gmail.com>");
	n += StrcopyW(about_message + n, TEXTLEN - n, L"\n\nCompiled on ");
	Asciitounicode(__DATE__, SHORTNAME, buf, SHORTNAME);
	n += StrcopyW(about_message + n, TEXTLEN - n, buf);
	n += StrcopyW(about_message + n, TEXTLEN - n, L" ");
	Asciitounicode(__TIME__, SHORTNAME, buf, SHORTNAME);
	n += StrcopyW(about_message + n, TEXTLEN - n, buf);
	n += StrcopyW(about_message + n, TEXTLEN - n, L" with ");
	n += StrcopyW(about_message + n, TEXTLEN - n, L"MinGW32 ");
	StrcopyW(about_message + n, TEXTLEN - n, L"C compiler");
	MessageBox(hwollymain, about_message, L"About OllyGraph", MB_OK|MB_ICONINFORMATION);
	/* Suspendallthreads() and Resumeallthreads() must be paired, even if they */
	/* are called in inverse order! */
	Suspendallthreads();
}

/**
 * @menu_handler
 *
 *      Menu callback for our plugin to process our menu commands.
 */
int menu_handler(t_table *pTable, wchar_t *pName, ulong index, int nMode)
{
	UNREFERENCED_PARAMETER(pTable);
	UNREFERENCED_PARAMETER(pName);

	switch (nMode) {
	case MENU_VERIFY:
		return MENU_NORMAL;

	case MENU_EXECUTE:
		switch (index) {
		case MENU_SETTINGS: /* Menu -> Settings */
			DialogBox(plugin_instance,
					  MAKEINTRESOURCE(IDD_SETTINGS),
					  hwollymain,
					  (DLGPROC)settings_dialog_procedure);
			break;
		case MENU_LIST_INTRAMODULE_CALLS:	/* Menu | Disasm Menu -> List Intramodule Calls */
			/* only execute if a module is loaded */
			if (Findmainmodule() == NULL) {
				MessageBox(hwollymain, L"No module loaded", L"OllyPlugin", MB_OK | MB_ICONINFORMATION);
			} else {
				if (call_table.hw == NULL) {
					Createtablewindow(&call_table, 0, call_table.bar.nbar, NULL, L"ICO_P", PLUGIN_NAME);
				} else {
					Activatetablewindow(&call_table);
				}
				find_intramodular_calls();
				return MENU_REDRAW;	/* force redrawing of the table after data is added to it */
			}
			break;
		case MENU_PROCEDURE_FLOWGRAPH: /* Menu | Disasm Menu -> Generate Procedure Flow Graph */
			generate_procedure_flow_graph();
			break;
		case MENU_PROCEDURE_CALL_GRAPH: /* Menu | Disasm Menu -> Generate Procedure Call Graph */
			generate_procedure_call_graph();
			break;
		case MENU_XREFS_TO_ADDRESS_GRAPH:	/* Menu | Disasm Menu -> Generate XRefs To Address Graph */
			break;
		case MENU_XREFS_FROM_ADDRESS_GRAPH:	/* Menu | Disasm Menu -> Generate XRefs From Address Graph */
			break;
		case MENU_ABOUT: /* Menu -> About */
			display_about_message();
			break;
		}
		return MENU_NOREDRAW;
	}

	return MENU_ABSENT;
}
/**
 *
 * Intramodule calls
 *
 **/

int initialize_call_table(void)
{
	if (Createsorteddata(&call_table.sorted, sizeof(t_call_table), 1, NULL, NULL, 0) == -1) {
		Addtolist(0, DRAW_HILITE, L"%s: Unable to created sorted table data.", PLUGIN_NAME);
		return -1;
	}

	StrcopyW(call_table.name, SHORTNAME, PLUGIN_NAME);
	call_table.bar.name[0] = L"Address";
	call_table.bar.expl[0] = L"";
	call_table.bar.mode[0] = BAR_SORT;
	call_table.bar.defdx[0] = 9;

	call_table.bar.name[1] = L"Command";
	call_table.bar.expl[1] = L"";
	call_table.bar.mode[1] = BAR_FLAT;
	call_table.bar.defdx[1] = 40;

	call_table.bar.name[2] = L"Dest";
	call_table.bar.expl[2] = L"";
	call_table.bar.mode[2] = BAR_SORT;
	call_table.bar.defdx[2] = 9;

	call_table.bar.name[3] = L"Dest name";
	call_table.bar.expl[3] = L"";
	call_table.bar.mode[3] = BAR_FLAT;
	call_table.bar.defdx[3] = 35;

	call_table.bar.name[4] = L"Comments";
	call_table.bar.expl[4] = L"";
	call_table.bar.mode[4] = BAR_FLAT;
	call_table.bar.defdx[4] = 80;

	call_table.bar.nbar = 5;
	call_table.mode = TABLE_SAVEALL;
	call_table.bar.visible = 1;
	call_table.custommode = 0;
	call_table.customdata = NULL;
	call_table.updatefunc = NULL;
	call_table.tabfunc = (TABFUNC *)call_table_func;
	call_table.drawfunc = (DRAWFUNC *)draw_call_table;
	call_table.tableselfunc = NULL;
	call_table.menu = NULL;

	return 0;
}

int draw_call_table(wchar_t *s, uchar *mask, int *select, t_table *pt, t_drawheader *ph, int column, void *cache)
{
	int	str_len = 0;
	t_call_table *local_table = (t_call_table *)ph;

	switch (column) {
	case 0:	/* address of call */
		str_len = Simpleaddress(s, local_table->addr, mask, select);
		break;
	case 1: /* decoded command */
		str_len = StrcopyW(s, TEXTLEN, local_table->command);
		break;
	case 2: /* call's destination address */
		str_len = Simpleaddress(s, local_table->dest_addr, mask, select);
		break;
	case 3: /* destination name */
		str_len = StrcopyW(s, TEXTLEN, local_table->dest_name);
		break;
	case 4: /* comments of command */
		str_len = StrcopyW(s, TEXTLEN, local_table->comment);
		break;
	default:
		break;
	}
	return str_len;
}

long call_table_func(t_table *pTable, HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	t_call_table *pTableData;
	switch (uMsg) {
	case WM_USER_CREATE:
		Setautoupdate(&call_table, 1);
		break;
	case WM_USER_UPD:		/* Autoupdate contents of the window */
		InvalidateRect(pTable->hw, NULL, FALSE);
		break;
	case WM_USER_DBLCLK:
		pTableData = (t_call_table *)Getsortedbyselection(&pTable->sorted, pTable->sorted.selected);
		if (pTableData != NULL) {
			Setcpu(0, pTableData->addr, 0, 0, 0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
		}
		return 1;
	default:
		break;
	}
	return 0;
}

void find_intramodular_calls(void)
{
	t_dump		*cpuasm			= NULL;
	t_module	*main_module	= NULL;
	t_jmp		*calls			= NULL;
	ulong		i				= 0;

	uchar		*decoding_data	= NULL;
	ulong		decode_len		= 0;
	ulong		cmd_len			= 0;
	uchar		cmd[MAXCMDSIZE];
	t_reg		*reg			= NULL;
	t_disasm	disasm;
	ulong		dest_addr		= 0;
	sd_pred		*prediction		= NULL;

	/* clear call table */
	Deletesorteddatarange(&call_table.sorted, 0, 0xFFFFFFFF);

	cpuasm = Getcpudisasmdump();
	main_module = Findmainmodule();
	calls = Findjumpfrom(main_module->base);

	i = 0;
	while (calls[i].from != 0xFFFFFFFF) {
		if ((calls[i].type & JT_TYPE) == JT_CALL ||
				(calls[i].type & JT_TYPE) == JT_SWCALL) {

			/* use local variable for readability and to get predictions*/
			dest_addr = calls[i].dest;

			/* if we have 'CALL ESI' or something similar the calls[i].dest
			 * will be 0. Check if OllyDbg can predict the address in the register
			 */
			if (dest_addr == 0) {
				prediction = (sd_pred *)Findsimpledata(&(main_module->predict), calls[i].from);
				if (prediction != NULL &&
						(prediction->mode & (PRED_VALID|PRED_ADDR|PRED_ORIG|PRED_OMASK)) == PRED_VALID
				   ) {
					/* For some reason OllyDbg will have predicted information if the call
					 * destination is a DWORD PTR to an address within the module, but
					 * that address is not stored in 'resconst'
					 */
					dest_addr = prediction->resconst;
					//Addtolist(calls[i].from, DRAW_HILITE, L"Predicted address: %08X    Destination: %08X", calls[i].from, dest_addr);
				} else if (prediction != NULL &&
						   (prediction->mode & (PRED_VALID|PRED_ADDR|PRED_ORIG|PRED_OMASK)) == (PRED_VALID|PRED_ADDR) &&
						   (Readmemory(&dest_addr, prediction->resconst, sizeof(ulong), MM_SILENT) != 0)
						  ) {
					//Addtolist(calls[i].from, DRAW_HILITE, L"Predicted address: %08X    Indirect destination: [%08X]=%08X", calls[i].from, prediction->resconst, dest_addr);
					dest_addr = prediction->resconst;
				}
			}

			/* if the destination is withing the module add it to the call table */
			if (dest_addr >= main_module->entry &&
					dest_addr <= main_module->entry + main_module->codesize) {

				/*get command */
				decoding_data = Finddecode(calls[i].from, &decode_len);
				cmd_len = Readmemory(cmd, calls[i].from, MAXCMDSIZE, MM_SILENT|MM_PARTIAL);
				reg = Threadregisters(cpuasm->threadid);
				Disasm(cmd, cmd_len, calls[i].from, decoding_data, &disasm, DA_TEXT|DA_OPCOMM|DA_MEMORY, reg, NULL);

				/* add new data to call table */
				t_call_table new_data;
				new_data.addr = calls[i].from;
				new_data.size = 1;
				new_data.type = 0;
				StrcopyW(new_data.command, TEXTLEN, disasm.result);
				new_data.dest_addr = dest_addr;
				Decodeaddress(dest_addr, 0, DM_WIDEFORM|DM_MODNAME, new_data.dest_name, TEXTLEN, NULL);
				StrcopyW(new_data.comment, TEXTLEN, disasm.comment);
				Addsorteddata(&(call_table.sorted), &new_data);
			}
		}
		i++;
	}
}

/**
 *
 * OllyDbg internal functions
 *
 */

/**
 * @DllMain
 *
 *      Dll entrypoint - mainly unused.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
		plugin_instance = hinstDll;		/* Save plugin instance */
	}
	return 1;							/* Report success */
};

/**
 * @ODBG2_Pluginquery - required!
 *
 *      Handles initializing the plugin.
 */
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion, ulong *features, wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
	if (ollydbgversion < 201) {
		return 0;
	}
	/* Report name and version to OllyDbg */
	StrcopyW(pluginname, SHORTNAME, PLUGIN_NAME);
	StrcopyW(pluginversion, SHORTNAME, PLUGIN_VERS);
	return PLUGIN_VERSION;			/* Expected API version */
};

/**
 * @ODBG2_Plugininit - optional
 *
 *      Handles one-time initializations and allocate resources.
 */
extc int __cdecl ODBG2_Plugininit(void)
{
	int ret = 0;

	Addtolist(0, DRAW_NORMAL, L"");
	Addtolist(0, DRAW_NORMAL, L"[*] %s v%s", PLUGIN_NAME, PLUGIN_VERS);
	Addtolist(0, DRAW_NORMAL, L"[*] Coded by: Austyn Krutsinger <akrutsinger@gmail.com>");
	Addtolist(0, DRAW_NORMAL, L"");

	ret = initialize_call_table();
	if (ret == -1) {
		return ret;
	}

	load_settings(NULL);

	/* Report success. */
	return 0;
};

/**
 * @ODBG2_Pluginmenu
 *
 *      Adds items to OllyDbgs menu system.
 */
extc t_menu *__cdecl ODBG2_Pluginmenu(wchar_t *type)
{
	if (wcscmp(type, PWM_MAIN) == 0) {
		/* Main menu. */
		return ollygraph_menu;
	} else if (wcscmp(type, PWM_DISASM) == 0) {
		/* Disassembler pane of CPU window. */
		return ollygraph_popup_menu;
	}
	return NULL;                /* No menu */
};

extc void __cdecl ODBG2_Pluginreset(void)
{
	Deletesorteddatarange(&call_table.sorted, 0, 0xFFFFFFFF);
	delete_gdl_files();

#ifdef FIND_MEMORY_LEAKS
	report_mem_leak();
#endif
}

extc void __cdecl ODBG2_Plugindestroy(void)
{
	Destroysorteddata(&call_table.sorted);
	delete_gdl_files();

#ifdef FIND_MEMORY_LEAKS
	report_mem_leak();
#endif
}
