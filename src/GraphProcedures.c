#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "resource.h"
#include "plugin.h"
#include "GraphProcedures.h"
#include "settings.h"

#ifdef FIND_MEMORY_LEAKS
	#include	"MemCheck.h"
#endif /* FIND_MEMORY_LEAKS */

extern HINSTANCE plugin_instance;

struct edge_info_s {
	DWORD	src_addr;
	DWORD	dst_if_true;
	DWORD	dst_if_false;
	BOOL	conditional_jmp;
};

/* module specific globals */
static char flow_graph_vcg_params[] =	"manhattan_edges: yes\n"
										"layoutalgorithm: mindepth\n"
										"finetuning: yes\n"
										"port_sharing: no\n"
										"layout_downfactor: 100\n"
										"layout_upfactor: 0\n"
										"layout_nearfactor: 0\n"
										"xlspace: 12\n"
										"yspace: 30\n";

static char call_graph_vcg_params[] =	"manhattan_edges: no\n"
										"layoutalgorithm: maxdepthslow\n"
										"finetuning: yes\n"
										"port_sharing: no\n"
										"layout_downfactor: 100\n"
										"layout_upfactor: 0\n"
										"layout_nearfactor: 0\n"
										"xlspace: 12\n"
										"yspace: 30\n";

int run_wingraph32(wchar_t *gdl_file_name, int *regenerate_graph)
{
	int ret = (int)ShellExecute(hwollymain, L"open", global_wingraph32_path, gdl_file_name, NULL, SW_SHOWNORMAL);
	if (ret == ERROR_FILE_NOT_FOUND ||
		ret == ERROR_PATH_NOT_FOUND ||
		ret == SE_ERR_FNF ||
		ret == SE_ERR_PNF) {

		ret = MessageBox(hwollymain,
							L"Could not find wingraph32.\n\n"
							"Would you like OllyGraph to put a copy of wingraph32.exe in the plugin directory?",
							plugindir,
							MB_YESNO|MB_ICONEXCLAMATION);

		/* Copy wingraph32 from the the .rsrc section to the plugin directory */
		if (ret == IDYES) {
			HRSRC exe_resource = FindResource(plugin_instance, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
			if (exe_resource) {
				unsigned int exe_resource_size = SizeofResource(plugin_instance, exe_resource);
				if (exe_resource_size) {
					HGLOBAL exe_resource_data = LoadResource(plugin_instance, exe_resource);
					if (exe_resource_data) {
						void * exe_data = LockResource(exe_resource_data);
						if (exe_data) {
							wchar_t output_path[MAX_PATH];
							wcscpy(output_path, plugindir);
							wcscat(output_path, L"\\wingraph32.exe");
							HANDLE hFile = CreateFile(output_path,		// name of the write
											   GENERIC_WRITE,			// open for writing
											   0,						// do not share
											   NULL,					// default security
											   CREATE_NEW,				// create new file only
											   FILE_ATTRIBUTE_NORMAL,	// normal file
											   NULL);					// no attr. template
							if (hFile == INVALID_HANDLE_VALUE) {
								MessageBox(hwollymain, L"CreateFile failed", L"OllyGraph", MB_OK|MB_ICONEXCLAMATION);
							} else {
								DWORD dwBytesWritten = 0;
								ret = WriteFile(
												hFile,				// open file handle
												exe_data,			// start of data to write
												exe_resource_size,	// number of bytes to write
												&dwBytesWritten,	// number of bytes that were written
												NULL);				// no overlapped structure
								CloseHandle(hFile);
								*regenerate_graph = 1;	/* Set flag after file created to graph again */
							}
						} else { /* !exe_data */
							MessageBox(hwollymain, L"LockResource failed", L"OllyGraph", MB_OK|MB_ICONEXCLAMATION);
						}
					} else {	/* !exe_resource_data */
						MessageBox(hwollymain, L"LoadResource failed", L"OllyGraph", MB_OK|MB_ICONEXCLAMATION);
					}
				} else {	/* !exe_resource_size */
					MessageBox(hwollymain, L"SizeOfResource failed", L"OllyGraph", MB_OK|MB_ICONEXCLAMATION);
				}
			} else {	/* !exe_resource */
				MessageBox(hwollymain, L"FindResource failed", L"OllyGraph", MB_OK|MB_ICONEXCLAMATION);
			}
		}

	} else if (ret < 32) {	/* ShellExecute return value */
		MessageBox(hwollymain,
					L"Error executing wingraph32",
					L"OllyGraph", MB_OK|MB_ICONEXCLAMATION);
	}

	return ret;
}

void generate_procedure_flow_graph(void)
{
	HANDLE gdl_file = NULL;	/* handle to temporary .gdl file */
	wchar_t gdl_file_name[MAX_PATH];
	DWORD proc_start_addr = 0;
	DWORD proc_end_addr = 0;
	int regenerate_flow_graph = 0;
	t_dump *cpuasm;

	static struct node_s	nodes;	/* main list used to store all nodes found */
	struct list_head *pos, *q;	/* used to keep position while iterating through list in list_for_each() */
	struct disasm_s *tmp;
	struct disasm_s	disassembled_proc; /* struct with entire procedure disassembled */
	struct node_s *tmp_node = NULL;

	/* check if main module is loaded */
    if (Findmainmodule() == NULL) {
		MessageBox(hwollymain,
			L"You must load a module before generating a graph.",
			L"No module loaded", MB_OK|MB_ICONEXCLAMATION);
		return;
    }

	/* initialize lists */
	INIT_LIST_HEAD(&disassembled_proc.list);
	INIT_LIST_HEAD(&nodes.list);
	nodes.count = 0;

	/* create a temporary file (hopefully cached) for writing to */
	gdl_file = create_gdl_file(gdl_file_name);
	if (gdl_file == NULL) {
		MessageBox(hwollymain,
			L"Could not create temporary file",
			L"CreateFile Error", MB_OK|MB_ICONEXCLAMATION);
		goto cleanup;
	}

	cpuasm = Getcpudisasmdump();

	/* find the start and end address of the procedure with the selected instruction */
	if (Getproclimits(cpuasm->sel0, &proc_start_addr, &proc_end_addr) == -1) {
		MessageBox(hwollymain,
			L"Address is not within known function boundaries\n"
			L"(Did you run Analyze Code?)",
			L"Function boundaries not found", MB_OK|MB_ICONEXCLAMATION);
		goto cleanup;
	}

	/* write first part of graph file */
	write_gdl_file(gdl_file, "graph: {\ntitle: \"Graph of %x\"\n%s", proc_start_addr, flow_graph_vcg_params);

	/* disassemble each instruction and save each possible node starting address */
	find_flow_graph_nodes(&nodes, cpuasm, &disassembled_proc, proc_start_addr, proc_end_addr);

	/* Enumerate all nodes and determine the type jump (jmp, jnz, jne, et cetera) */
	find_flow_graph_edges(&nodes, gdl_file, &disassembled_proc, proc_start_addr, proc_end_addr);

	/* run wingraph32 with created .gld file */
	run_wingraph32(gdl_file_name, &regenerate_flow_graph);

cleanup:
	/* free disassembly list */
	list_for_each_safe(pos, q, &disassembled_proc.list) {
		tmp = list_entry(pos, struct disasm_s, list);
		list_del(pos);
		Memfree(tmp);
	}

	/* free nodes list */
	list_for_each_safe(pos, q, &nodes.list) {
		tmp_node = list_entry(pos, struct node_s, list);
		list_del(pos);
		Memfree(tmp_node);
	}

	if (gdl_file != NULL) {
		CloseHandle(gdl_file);
		gdl_file = NULL;
	}

	/* wingraph32.exe was dropped; graph again so the user doesn't have to */
	if (regenerate_flow_graph == 1) {
		generate_procedure_flow_graph();
	}
}

void create_call_graph_nodes_and_edges(struct node_s *nodes, const t_dump *cpuasm, const DWORD start_addr, const DWORD caller_addr, char **buffer, char *edge_str)
{
	/* prepare local variables */
	DWORD		psize			= 0;
	DWORD		dsize 			= 0;
	DWORD		next_addr		= 0;
	DWORD		current_addr	= start_addr;
	DWORD		end_addr		= 0;
	DWORD		blocksize		= 0;
	uchar		*decode	= NULL;
	t_reg		*reg	= NULL;
	uchar		cmdbuf[MAXCMDSIZE]	= {0};
	t_disasm	disasm_result;

	t_module	*current_module	= NULL;
	DWORD		dest_addr		= 0;
	sd_pred		*prediction		= NULL;

	/* TODO: if routine calls itself, add an edge and return */
	if (start_addr == caller_addr) {
		list_add_node_unique(nodes, start_addr, NODE_NORMAL);
		asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" }\n", *buffer, start_addr, start_addr);
		return;
	}

	current_module = Findmodule(start_addr);

	Getproclimits(start_addr, &current_addr, &end_addr);	/* start_addr and current_addr will always be the same here */

	blocksize = end_addr - start_addr + 16;	/* give a 16 byte buffer so the last command of the procedure can be read */

	do {
		/* decode current command information and determine command size in bytes */
		current_addr += psize;
		decode = Finddecode(current_addr, &dsize);
		Readmemory(cmdbuf, current_addr, MAXCMDSIZE, MM_SILENT|MM_PARTIAL);
		next_addr = Disassembleforward(NULL, start_addr, blocksize, current_addr, 1, USEDECODE);
		psize = next_addr - current_addr;
		if (psize <= 0) {
			psize = 1;
		}
		reg = Threadregisters(cpuasm->threadid);
		Disasm(cmdbuf, psize, current_addr, decode, &disasm_result, DA_TEXT|DA_OPCOMM|DA_MEMORY, reg, NULL);

		if (((disasm_result.cmdtype & D_CMDTYPE) == D_CALL ) ||
			((disasm_result.cmdtype & D_CMDTYPE) == D_CALLFAR)) {
			/* command is a call */

			/* command could be CALL ESI or CALL ESP or something similar */
			if (disasm_result.jmpaddr == 0) {
				prediction = (sd_pred *)Findsimpledata(&(current_module->predict), current_addr);
				if (prediction != NULL &&
					(prediction->mode & (PRED_VALID|PRED_ADDR|PRED_ORIG|PRED_OMASK)) == PRED_VALID
				) {
					/* For some reason OllyDbg will have predicted information if the call
					 * destination is a DWORD PTR to an address withing the module, but
					 * that address is not stored in 'resconst'
					 */
					dest_addr = prediction->resconst;
					//Addtolist(current_addr, DRAW_HILITE, L"Predicted address: %08X    Destination: %08X", current_addr, dest_addr);
//My husband is sooooo smart-except he can't get this to work
					//wchar_t function_name[TEXTLEN] = { 0 };
					//Decodeknownbyaddr(dest_addr, NULL, NULL, NULL, function_name, -1, 1);
					//Addtolist(current_addr, DRAW_HILITE, L"[%.8X] - %s", dest_addr, function_name);
				} else if (prediction != NULL &&
					(prediction->mode & (PRED_VALID|PRED_ADDR|PRED_ORIG|PRED_OMASK)) == (PRED_VALID|PRED_ADDR) &&
					(Readmemory(&dest_addr, prediction->resconst, sizeof(ulong), MM_SILENT) != 0)
				) {
					//Addtolist(current_addr, DRAW_HILITE, L"Predicted address: %08X    Indirect destination: [%08X]=%08X", current_addr, prediction->resconst, dest_addr);
					dest_addr = prediction->resconst;
				}
			} else {
				/* otherwise label the node as the target address of the call */
				dest_addr = disasm_result.jmpaddr;
			}

			/* only delve into functions that are within the current module */
			if ((dest_addr >= current_module->codebase) &&
				(dest_addr <= current_module->codebase + current_module->codesize)) {

				/* add node to list and save edge with the color of a intramodular call */
				list_add_node_unique(nodes, dest_addr, NODE_NORMAL);
				asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" color: 16 }\n", *buffer, start_addr, dest_addr);

				create_call_graph_nodes_and_edges(nodes, cpuasm, dest_addr, current_addr, buffer, edge_str);
			} else {
				/* edge color is black because it's a call to a system function */
				list_add_node_unique(nodes, dest_addr, NODE_SYSTEMCALL);
				asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" }\n", *buffer, start_addr, dest_addr);
			}
		}
	} while (current_addr < end_addr);
}

void generate_procedure_call_graph(void)
{
	HANDLE		gdl_file	= NULL;	/* handle to temporary .gdl file */
	wchar_t		gdl_file_name[MAX_PATH];
	t_dump		*cpuasm		= NULL;
	DWORD		proc_start_addr	= 0;
	DWORD		proc_end_addr	= 0;
	int			regenerate_call_graph = 0;
	struct node_s	nodes;	/* main list used to store all nodes found */
	struct list_head *pos, *q;	/* used to keep position while iterating through list in list_for_each() */
	struct node_s *tmp_node = NULL;

	char **buffer = NULL;	/* pointer to edge_str. use a pointer to a pointer for dynamic allocation of strings */
	char *edge_str = NULL;

	/* check if main module is loaded */
    if (Findmainmodule() == NULL) {
		MessageBox(hwollymain,
			L"You must load a module before generating a graph.",
			L"No module loaded", MB_OK|MB_ICONEXCLAMATION);
		return;
    }

	INIT_LIST_HEAD(&nodes.list);
	nodes.count = 0;

	/* Allocate enough memory for pointer-to-pointer to hold a pointer to char. */
	buffer = (char **)Memalloc(sizeof(buffer), SILENT|ZEROINIT);
	if (buffer == NULL) {
		MessageBox(hwollymain,
			L"Could not allocate memory",
			L"Memalloc Error", MB_OK|MB_ICONEXCLAMATION);
		return;
	}
	/* Good practice: always initialize *buffer. */
	*buffer = "\0";

	/* create a temporary file (hopefully cached) for writing to */
	gdl_file = create_gdl_file(gdl_file_name);
	if (gdl_file == NULL) {
		MessageBox(hwollymain,
			L"Could not create temporary file",
			L"CreateFile Error", MB_OK|MB_ICONEXCLAMATION);
		goto cleanup;
	}

	cpuasm = Getcpudisasmdump();

	/* find the start and end address of the procedure with the selected instruction */
	if (Getproclimits(cpuasm->sel0, &proc_start_addr, &proc_end_addr) == -1) {
		MessageBox(hwollymain,
			L"Address is not within known function boundaries\n"
			L"(Did you run Analyze Code?)",
			L"Function boundaries not found", MB_OK|MB_ICONEXCLAMATION);
		goto cleanup;
	}

	/* write first part of graph file */
	write_gdl_file(gdl_file, "graph: {\ntitle: \"Graph of %x\"\n%s", proc_start_addr, call_graph_vcg_params);

	/* make sure very first calling procedure is added to the nodes list */
	list_add_node_unique(&nodes, proc_start_addr, NODE_START);

	/* recursively iterate through all calls in procedure */
	create_call_graph_nodes_and_edges(&nodes, cpuasm, proc_start_addr, 0, buffer, edge_str);

	/* write nodes to gdl file */
	list_for_each_entry(tmp_node, &nodes.list, list) {
		write_gdl_file(gdl_file, "node: { label: \"%.8X\" title: \"%.8X\" color: %i }\n", tmp_node->addr, tmp_node->addr, tmp_node->type);
	}

	/* write edge list and final closing brace */
	edge_str = *buffer;
	write_gdl_file(gdl_file, "%s}\n", edge_str);

	run_wingraph32(gdl_file_name, &regenerate_call_graph);

cleanup:
	/* free allocated memory */
	if (edge_str != NULL) {
		Memfree(edge_str);
	}
	if (buffer != NULL) {
		Memfree(buffer);
	}

	/* free nodes list */
	list_for_each_safe(pos, q, &nodes.list) {
		tmp_node = list_entry(pos, struct node_s, list);
		list_del(pos);
		Memfree(tmp_node);
	}

	if (gdl_file != NULL) {
		CloseHandle(gdl_file);
		gdl_file = NULL;
	}

	/* wingraph32.exe was dropped; graph again so the user doesn't have to */
	if (regenerate_call_graph == 1) {
		generate_procedure_call_graph();
	}
}

void find_flow_graph_nodes(struct node_s *nodes, const t_dump *cpuasm, struct disasm_s *disassmbled_proc, const DWORD start_addr, const DWORD end_addr)
{
	/* prepare local variables */
	DWORD		psize			= 0;
	DWORD		dsize 			= 0;
	DWORD		next_addr		= 0;
	DWORD		current_addr	= start_addr;
	DWORD		blocksize = end_addr - start_addr + 16;	/* give a 16 byte buffer so the last command of the procedure can be read */
	BOOL		save_next_address = TRUE;
	uchar		*decode	= NULL;
	t_reg		*reg	= NULL;
	uchar		cmdbuf[MAXCMDSIZE]	= {0};
	t_disasm	disasm_result;
	struct disasm_s	*tmp = NULL;

	do {
		/* decode current command information and determine command size in bytes */
		current_addr += psize;
		decode = Finddecode(current_addr, &dsize);
		Readmemory(cmdbuf, current_addr, MAXCMDSIZE, MM_SILENT|MM_PARTIAL);
		next_addr = Disassembleforward(NULL, start_addr, blocksize, current_addr, 1, USEDECODE);
		psize = next_addr - current_addr;
		if (psize <= 0) {
			psize = 1;
		}
		reg = Threadregisters(cpuasm->threadid);
		Disasm(cmdbuf, psize, current_addr, decode, &disasm_result, DA_TEXT|DA_OPCOMM|DA_MEMORY, reg, NULL);

		/* save the disassembled command into the procedure structure */
		tmp = (struct disasm_s *)Memalloc(sizeof(struct disasm_s), SILENT|ZEROINIT);
		tmp->disasm_result = disasm_result;

		/* makes the list point to the allocated memory pointed to by tmp.
		 * this will be free'd at the end of the generate_function_flow_graph() function
		 */
		list_add_tail(&(tmp->list), &(disassmbled_proc->list));

		/* enumerate nodes */
		if (save_next_address == TRUE) {
			list_add_node_unique(nodes, current_addr, NODE_NORMAL);
			save_next_address = FALSE;
		}
		if ((disasm_result.jmpaddr >= start_addr) && (disasm_result.jmpaddr < end_addr)) {
			/* this is a jump; start of an edge and pointer to a node */
			list_add_node_unique(nodes, disasm_result.jmpaddr, NODE_NORMAL);
			save_next_address = TRUE; /* ensure the next command is updated because it will be  update current_addr node on next pass */
		}
	} while (current_addr < end_addr);
}

void find_flow_graph_edges(struct node_s *nodes, HANDLE *file, struct disasm_s *disassmbled_proc, const DWORD start_addr, const DWORD end_addr)
{
	DWORD current_node_addr = start_addr;
	BOOL orphan_node = FALSE;
	BOOL node_has_been_written = FALSE; /* flag is used to know when to place a closing brace around a "node" block */
	struct disasm_s *tmp = NULL;
	struct edge_info_s edge_info;	/* keep information about last edge for comparison and easy interpretation */

	char **buffer = NULL;	/* pointer to edge_str. use a pointer to a pointer for dynamic allocation of strings */
	char *edge_str = NULL;

	/* Allocate enough memory for pointer-to-pointer to hold a pointer to char. */
	buffer = (char **)Memalloc(sizeof(buffer), SILENT|ZEROINIT);
	if (buffer == NULL) {
		MessageBox(hwollymain,
			L"Could not allocate memory",
			L"Memalloc Error", MB_OK|MB_ICONEXCLAMATION);
		return;
	}
	/* Good practice: always initialize *buffer. */
	*buffer = "\0";

	edge_info.conditional_jmp = FALSE;	/* must assume first jump is not conditional */

	list_for_each_entry(tmp, &disassmbled_proc->list, list) {

		if (list_contains_node(nodes, tmp->disasm_result.ip) == TRUE) {
			if (orphan_node == TRUE) {
				asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" }\n", *buffer, current_node_addr, tmp->disasm_result.ip);
			}

			/* assume this node has no jump/branch, but some other instruction later on jumps to
			 * an instruction within the code block */
			orphan_node = TRUE;
			current_node_addr = tmp->disasm_result.ip;
			if (node_has_been_written == TRUE) {
				write_gdl_file(file, "\" }\n");
			}
			write_gdl_file(file, "node: { title: \"%.8X\" label: \"%.8X:", current_node_addr, current_node_addr);
			node_has_been_written = TRUE;
		}

		/* save the command or command with comment */
		if (StrlenW(tmp->disasm_result.comment, TEXTLEN) > 0) {
			wchar_t cleaned_comment[TEXTLEN];
			add_escape_characters(tmp->disasm_result.comment, cleaned_comment);
			write_gdl_file_utf16(file, L"\n%-30s\t; %s", tmp->disasm_result.result, cleaned_comment);
		} else {
			write_gdl_file_utf16(file, L"\n%s", tmp->disasm_result.result);
		}

		if (edge_info.conditional_jmp == TRUE) {
            edge_info.dst_if_false = current_node_addr;	/* since jump was not taken, the current node address
														 * will be the next address to be executed */

			asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" label: \"false\" color: red }\n", *buffer, edge_info.src_addr, edge_info.dst_if_false);
			asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" label: \"true\" color: darkgreen }\n", *buffer, edge_info.src_addr, edge_info.dst_if_true);

            edge_info.conditional_jmp = FALSE;
		}

		/* only look at jumps withing the bounds of the procedure being analyzed */
		if ((tmp->disasm_result.jmpaddr >= start_addr) && (tmp->disasm_result.jmpaddr < end_addr)) {
			orphan_node = FALSE;
			edge_info.src_addr = current_node_addr;
			edge_info.dst_if_true = tmp->disasm_result.jmpaddr;	/* only a true jump */
			edge_info.conditional_jmp = TRUE;	/* assume jump will be conditional */

			if ((*tmp->disasm_result.result == 'J') && (*(tmp->disasm_result.result+1) == 'M')) {
				/* straight JMP, no true/false values */
				asprintf(buffer, "%sedge: { sourcename: \"%.8X\" targetname: \"%.8X\" }\n", *buffer, edge_info.src_addr, edge_info.dst_if_true);
				edge_info.conditional_jmp = FALSE;
			}
		}
	}

	/* close last node */
	write_gdl_file(file, "\" vertical_order: %d }\n", nodes->count);

	/* write edge list and final closing brace */
	edge_str = *buffer;
	write_gdl_file(file, "%s}\n", edge_str);

	/* free allocated memory */
	if (edge_str != NULL) {
		Memfree(edge_str);
	}
	if (buffer != NULL) {
		Memfree(buffer);
	}
}

HANDLE *create_gdl_file(wchar_t *name)
{
	HANDLE *file;
	wchar_t path[MAX_PATH];

	GetTempPath(MAX_PATH, path);

	GetTempFileName(path, L"ogh", 0, name);
	file = CreateFile(name, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_RANDOM_ACCESS, NULL);

	return file;
}

void delete_gdl_files(void)
{
	WIN32_FIND_DATA find_file_data;
	HANDLE file;
	wchar_t temp_dir_path[MAX_PATH];
	wchar_t found_file[MAX_PATH];
	DWORD error;

	GetTempPath(MAX_PATH, temp_dir_path);
	wcsncat(temp_dir_path, L"ogh*.tmp", 8);
	file = FindFirstFile(temp_dir_path, &find_file_data);
	/* reset the temp directory path so we don't have to allocate more space on the stack for another buffer */
	/* if temp_dir_path is not reset "ogh*.tmp" will be prepended to the found filename. exempli gratia "/ogh*.tmpoghACB2.tmp" */
	GetTempPath(MAX_PATH, temp_dir_path);

	if (file == INVALID_HANDLE_VALUE) {
		return;
	} else {
		StrcopyW(found_file, MAX_PATH, temp_dir_path);
		wcscat(found_file, find_file_data.cFileName);
		DeleteFile(found_file);
		while (FindNextFile(file, &find_file_data) != 0) {
			StrcopyW(found_file, MAX_PATH, temp_dir_path);
			wcscat(found_file, find_file_data.cFileName);
			DeleteFile(found_file);
		}

		error = GetLastError();
		if (error == ERROR_NO_MORE_FILES) {
			FindClose(file);
		}
	}
}

void __write_gdl_file(HANDLE file, const char *format, va_list args)
{
	char *buffer = NULL;
	DWORD buffer_len;
	DWORD print_len;
	DWORD write_len;

	buffer_len = vsnprintf(NULL, 0, format, args) + 1;
	buffer = (char *)Memalloc(buffer_len * sizeof(char), SILENT|ZEROINIT);
	if (buffer != NULL) {
		print_len = vsnprintf(buffer, buffer_len, format, args);
		WriteFile(file, buffer, print_len, &write_len, NULL);
		Memfree(buffer);
	} else {
		Addtolist(0, DRAW_HILITE, L"Could not allocate buffer used to write data to file.");
	}
}

void write_gdl_file(HANDLE file, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	__write_gdl_file(file, format, args);
	va_end(args);
}

BOOL list_contains_node(struct node_s *nodes, DWORD addr)
{
	struct node_s *tmp;

	list_for_each_entry(tmp, &nodes->list, list) {
		if (tmp->addr == addr) {
			return TRUE;
		}
	}
	return FALSE;
}

void list_add_node_unique(struct node_s *nodes, DWORD addr, node_type_t type)
{
	struct node_s *tmp;

	if (list_contains_node(nodes, addr) == FALSE) {
		tmp = (struct node_s *)Memalloc(sizeof(struct node_s), SILENT|ZEROINIT);
		tmp->addr = addr;
		tmp->type = type;
		list_add_tail(&(tmp->list), &(nodes->list));
		nodes->count++;
	}
}

#define _countof(array) (sizeof(array)/sizeof(array[0]))
void write_gdl_file_utf16(HANDLE file, const wchar_t *format, ...)
{
	va_list args;
	wchar_t *w_buf = NULL;
	char *c_buf = NULL;
	DWORD buffer_len = 0;

	va_start(args, format);

	buffer_len = vsnwprintf(NULL, 0, format, args) + 1;
	w_buf = (wchar_t *)Memalloc(buffer_len * _countof(w_buf), SILENT|ZEROINIT);
	if (w_buf != NULL) {
		buffer_len = vsnwprintf(w_buf, buffer_len, format, args);

		c_buf = (char *)Memalloc(buffer_len * sizeof(c_buf), SILENT|ZEROINIT);
		if (c_buf != NULL) {
			Unicodetoascii(w_buf, TEXTLEN, c_buf, TEXTLEN);
			__write_gdl_file(file, c_buf, args);

			Memfree(c_buf);
		} else {
			Addtolist(0, DRAW_HILITE, L"Could not allocate memory to convert wchar to char.");
		}
		Memfree(w_buf);
	} else {
		Addtolist(0, DRAW_HILITE, L"Could not allocate memory to convert wchar to char.");
	}
	va_end(args);
}

int __vasprintf(char **str, const char *fmt, va_list ap)
{
	int ret = -1;
	va_list ap2;
	char *string, *newstr;
	size_t len;

	va_copy(ap2, ap);
	if ((string = malloc(TEXTLEN)) == NULL) {
		goto fail;
	}

	ret = vsnprintf(string, TEXTLEN, fmt, ap2);
	if (ret >= 0 && ret < TEXTLEN) { /* succeeded with initial alloc */
		*str = string;
	} else if (ret == INT_MAX || ret < 0) { /* Bad length */
		goto fail;
	} else {        /* bigger than initial, realloc allowing for null */
		len = (size_t)ret + 1;
		if ((newstr = realloc(string, len)) == NULL) {
			free(string);
			goto fail;
		} else {
			va_end(ap2);
			va_copy(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			if (ret >= 0 && (size_t)ret < len) {
				*str = newstr;
			} else { /* failed with realloc'ed string; give up */
				free(newstr);
				goto fail;
			}
		}
	}
	va_end(ap2);
	return (ret);

fail:
	*str = NULL;
	errno = ENOMEM;
	va_end(ap2);
	return (-1);
}

int asprintf(char **str, const char *fmt, ...)
{
	va_list ap;
	int ret;

	*str = NULL;
	va_start(ap, fmt);
	ret = __vasprintf(str, fmt, ap);
	va_end(ap);

	return ret;
}

void add_escape_characters(const wchar_t *src, wchar_t *cleaned)
{
	wchar_t *t;

	for (t = cleaned; *src; src++) {
		if (*src == L'"') {
			*t++ = L'\\';
			*t = L'"';
		} else if (*src == L'\\') {
			*t++ = L'\\';
			*t = L'\\';
		} else {
			*t = *src;
		}
		t++;
	}
	*t = L'\0';
}
