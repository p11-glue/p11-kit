{
    "function_name": "stack_{function}",
    "function_argument": "{argument_type} {argument_name}",
    "call_lower": "return funcs->{function}",
    "call_lower_argument": "{argument_name}",
    "function_body": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}p11_virtual *virt = (p11_virtual *)self;
{indent}CK_X_FUNCTION_LIST *funcs = virt->lower_module;
{indent}{call_lower} (funcs,
{call_lower_arglist_indent}{call_lower_arglist});
}}
    """,
    "entry_argument": "",       # unused
    "entry": "{function_name}",
    "outer": """
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */

{wrappers}

CK_X_FUNCTION_LIST p11_virtual_stack = {{
{indent}{{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */
{xentries}
}};
"""
}
