{
    "function_name": "binding_{function}",
    "function_argument": "",    # unused
    "call_lower": "*ret = funcs->{function}",
    "call_lower_argument": "*({argument_type} *)args[{argument_index}]",
    "function_body": """\
static void
{function_name} (ffi_cif *cif,
{arglist_indent}CK_RV *ret,
{arglist_indent}void* args[],
{arglist_indent}CK_X_FUNCTION_LIST *funcs)
{{
{indent}{call_lower} (funcs,
{call_lower_arglist_indent}{call_lower_arglist});
}}
    """,
    "entry_argument": "&ffi_type_{argument_ffi_type}",
    "entry": "{{ {function_name}, {{ {entry_arglist}, NULL }} }}",
    "outer": """
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */

{wrappers}

static const BindingInfo binding_info[] = {{
{xentries},
{indent}{{ 0, }}
}};
"""
}
