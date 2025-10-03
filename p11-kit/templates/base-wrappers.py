{
    "function_name": "base_{function}",
    "function_argument": "{argument_type} {argument_name}",
    "call_lower": "return funcs->{function}",
    "call_lower_argument": "{argument_name}",
    "function_body": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}p11_virtual *virt = (p11_virtual *)self;
{indent}CK_FUNCTION_LIST *funcs = virt->lower_module;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "function_body_v3": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}p11_virtual *virt = (p11_virtual *)self;
{indent}CK_FUNCTION_LIST_3_2 *funcs = virt->lower_module;
{indent}if (funcs->version.major < 3)
{indent}{indent}return CKR_FUNCTION_NOT_SUPPORTED;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "entry_argument": "",       # unused
    "entry": "{function_name}",
    "outer": """
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */

{wrappers}

CK_X_FUNCTION_LIST p11_virtual_base = {{
{indent}{{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */
{xentries}
}};
"""
}
