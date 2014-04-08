/*******************************************************************************
 * OllyGraph - settings.h
 *
 * Copyright (c) 2013, Austyn Krutsinger
 * All rights reserved.
 *
 * OllyGraph is free (as in "free beer")
 *
 ******************************************************************************/

#ifndef __OLLYGRAPH_SETTINGS_H_
#define __OLLYGRAPH_SETTINGS_H__

/* Global Declarations */
wchar_t global_wingraph32_path[MAX_PATH];
HINSTANCE plugin_instance;

/* Prototypes */
INT_PTR CALLBACK settings_dialog_procedure(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void save_settings(HWND hDlg);
void load_settings(HWND hDlg);

#endif	/* __OLLYGRAPH_SETTINGS_INCLUDED__ */
