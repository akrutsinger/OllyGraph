/*******************************************************************************
 * OllyGraph - settings.c
 *
 * Copyright (c) 2013, Austyn Krutsinger
 * All rights reserved.
 *
 * OllyGraph is free (as in "free beer")
 *
 ******************************************************************************/

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <ShellAPI.h>

#include "plugin.h"
#include "OllyGraph.h"
#include "settings.h"
#include "resource.h"

/* Globals Definitions - Program specific */
extern wchar_t	global_wingraph32_path[MAX_PATH];
extern HINSTANCE plugin_instance;

static int	wingraph32_path_changed	= FALSE;	/* Module specific indicator if wingraph32 path changed */

INT_PTR CALLBACK settings_dialog_procedure(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	int ret;
	switch (uMsg) {
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_OK:
			/* Save the settings */
			save_settings(hDlg);
			EndDialog(hDlg, 1);
			return TRUE;
		case IDC_CANCEL:
			/* End dialog without saving anything */
			EndDialog(hDlg, 0);
			return TRUE;
		case IDC_BROWSE:
			ret = Browsefilename(L"OllyGraph - Open wingraph32", global_wingraph32_path, L"*.txt", (wchar_t *)plugindir, L"txt", hwollymain, BRO_FILE);
			if (ret != 0) {
				SetDlgItemText(hDlg, IDC_WINGRAPH32_PATH, (LPCWSTR)global_wingraph32_path);
				wingraph32_path_changed = TRUE;
			}
			return TRUE;
		case IDC_WINGRAPH32_PATH:
			if (HIWORD(wParam) == EN_CHANGE) {
				wingraph32_path_changed = TRUE;
			}
			return TRUE;
		}
		return TRUE;
	case WM_SYSCHAR:
		if (GetFocus() == GetDlgItem(hDlg, IDC_WINGRAPH32_PATH)) {
			wingraph32_path_changed = TRUE;
		}
		return TRUE;
	case WM_DROPFILES: {
			HDROP hdrop = (HDROP)wParam;
			DragQueryFile(hdrop, 0, global_wingraph32_path, sizeof(global_wingraph32_path));
			DragFinish(hdrop);
			SetDlgItemText(hDlg, IDC_WINGRAPH32_PATH, (LPCWSTR)global_wingraph32_path);
			wingraph32_path_changed = TRUE;
			SetFocus(GetDlgItem(hDlg, IDC_WINGRAPH32_PATH));
			return TRUE;
		}
	case WM_CLOSE:
		DragAcceptFiles(hDlg, FALSE);
		EndDialog(hDlg, 0);
		return TRUE;
	case WM_INITDIALOG:
		/* Load settings from ollydbg.ini. If there is no
		 * setting already in the ollydbg.ini, set the default * values so we can save them if we want
		 */
		DragAcceptFiles(hDlg, TRUE);
		load_settings(hDlg);
		SetFocus(GetDlgItem(hDlg, IDC_CANCEL));
		return TRUE;
	}
	return FALSE;
}

void save_settings(HWND hDlg)
{
	/* Wingraph32 Path */
	if (wingraph32_path_changed == TRUE) {
		GetDlgItemText(hDlg, IDC_WINGRAPH32_PATH, global_wingraph32_path, MAXPATH);
		Writetoini(NULL, PLUGIN_NAME, L"Wingraph32 path", global_wingraph32_path);
	}
}

void load_settings(HWND hDlg)
{
	/* Local variables */
	int ret;
	int n;			/* Used for string concatination */

	/* Database Path */
	ret = Stringfromini(PLUGIN_NAME, L"Wingraph32 path", global_wingraph32_path, MAXPATH);
	if (ret == 0) {
		/* Set default wingraph32.exe file location in plugin directory */
		n = StrcopyW(global_wingraph32_path, MAXPATH, plugindir);
		n += StrcopyW(global_wingraph32_path + n, MAXPATH - n, L"\\wingraph32.exe");
	}
	SetDlgItemText(hDlg, IDC_WINGRAPH32_PATH, (LPCWSTR)global_wingraph32_path);
}
