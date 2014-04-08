#ifndef __GRAPHPROCEDURES_H__
#define __GRAPHPROCEDURES_H__

#include "list.h"

struct disasm_s {
	t_disasm disasm_result;
	struct list_head list;
};

typedef enum node_type_t {
	NODE_NORMAL			= 16,
	NODE_START			= 3,
	NODE_INTRAMODULE	= 16,
	NODE_SYSTEMCALL		= 4
} node_type_t;

struct node_s {
	DWORD addr;
	DWORD count;
	node_type_t type;
	wchar_t comment[TEXTLEN];
	struct list_head list;
};

/* procedures used by other .c files */
extern void generate_procedure_flow_graph(void);
extern void generate_procedure_call_graph(void);
extern void delete_gdl_files(void);

/* procedures internal to GraphProcedures.c */
int run_wingraph32(wchar_t *gdl_file_name, int *regenerate_graph);
HANDLE *create_gdl_file(wchar_t *name);
void __write_gdl_file(HANDLE file, const char *format, va_list args);
void write_gdl_file(HANDLE file, const char *format, ...);
void write_gdl_file_utf16(HANDLE file, const wchar_t *format, ...);
int __vasprintf(char **str, const char *fmt, va_list ap);
int asprintf(char **str, const char *fmt, ...);
void add_escape_characters(const wchar_t *src, wchar_t *cleaned);
void generate_function_flow_graph(void);
void find_flow_graph_nodes(struct node_s *nodes, const t_dump *cpuasm, struct disasm_s *disassmbled_proc, const DWORD start_addr, const DWORD end_addr);
void find_flow_graph_edges(struct node_s *nodes, HANDLE *file, struct disasm_s *disassmbled_proc, const DWORD start_addr, const DWORD end_addr);

BOOL list_contains_node(struct node_s *nodes, DWORD addr);
void list_add_node_unique(struct node_s *nodes, DWORD addr, node_type_t type);

#endif // __GRAPHPROCEDURES_H__
