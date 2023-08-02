#!/usr/bin/python

"""
SPDX-License-Identifier: BSD-3-Clause
"""

import io
import json

INDENT = "        "

# These functions should not appear in CK_X_FUNCTION_LIST
EXCLUDE_IN_X = [
    "C_GetFunctionList",
    "C_GetFunctionStatus",
    "C_CancelFunction",
    "C_GetInterfaceList",
    "C_GetInterface",
]

# Short-circuited functions in fixed closures
SHORT_FUNCTIONS = [
    "C_GetFunctionStatus",
    "C_CancelFunction",
]


def binding_function(function):
    name = f"binding_{function['name']}"
    name_indent = " " * len(name + " (")
    call = f"funcs->{function['name']}"
    call_indent = " " * len("*ret = " + call + " (")
    call_args_concatenated = ",\n".join([
        f"{INDENT}{call_indent}*({arg['type']} *)args[{i}]"
        for i, arg in enumerate(function["arguments"])
    ])
    return f'''\
static void
{name} (ffi_cif *cif,
{name_indent}CK_RV *ret,
{name_indent}void* args[],
{name_indent}CK_X_FUNCTION_LIST *funcs)
{{
{INDENT}*ret = {call} (funcs,
{call_args_concatenated});
}}

'''


def function_binding_info(function):
    args_concatenated = ", ".join([
        f"&ffi_type_{arg['ffi-type']}" for arg in function["arguments"]
    ])
    return (f"{INDENT}{{ binding_{function['name']}, "
            f"{{ {args_concatenated}, NULL }} }}")


def binding_info(functions):
    function_binding_info_concatenated = ",\n".join([
        function_binding_info(function) for function in functions
        if function["name"] not in EXCLUDE_IN_X
    ])
    return f'''\
static const BindingInfo binding_info[] = {{
{function_binding_info_concatenated},
{INDENT}{{ 0, }}
}};
'''


def stack_function(function):
    name = f"stack_{function['name']}"
    arg_indent = " " * len(name + " (")
    args = ",\n".join([
        f"{arg_indent}{arg['type']} {arg['name']}"
        for arg in function["arguments"]
    ])
    call = f"funcs->{function['name']}"
    call_indent = " " * len("return " + call + " (")
    call_args_concatenated = ",\n".join([
        f"{INDENT}{call_indent}{arg['name']}"
        for arg in function["arguments"]
    ])
    return f'''\
static CK_RV
{name} (CK_X_FUNCTION_LIST *self,
{args})
{{
{INDENT}p11_virtual *virt = (p11_virtual *)self;
{INDENT}CK_X_FUNCTION_LIST *funcs = virt->lower_module;
{INDENT}return {call} (funcs,
{call_args_concatenated});
}}

'''


def stack_function_list(functions):
    stack_functions_concatenated = ",\n".join([
        f"{INDENT}stack_{function['name']}" for function in functions
        if function["name"] not in EXCLUDE_IN_X
    ])
    return f'''\
CK_X_FUNCTION_LIST p11_virtual_stack = {{
{INDENT}{{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */
{stack_functions_concatenated}
}};
'''


def base_function(function):
    name = f"base_{function['name']}"
    arg_indent = " " * len(name + " (")
    args = ",\n".join([
        f"{arg_indent}{arg['type']} {arg['name']}"
        for arg in function["arguments"]
    ])
    call = f"funcs->{function['name']}"
    call_indent = " " * len("return " + call + " (")
    call_args_concatenated = f",\n{INDENT}{call_indent}".join([
        arg["name"] for arg in function["arguments"]
    ])

    if function["version"] > 2:
        function_list = "CK_FUNCTION_LIST_3_0"
        v3_guard = f'''
{INDENT}if (funcs->version.major < 3)
{INDENT}{INDENT}return CKR_FUNCTION_NOT_SUPPORTED;
'''
    else:
        function_list = "CK_FUNCTION_LIST"
        v3_guard = ""

    return f'''\
static CK_RV
{name} (CK_X_FUNCTION_LIST *self,
{args})
{{
{INDENT}p11_virtual *virt = (p11_virtual *)self;
{INDENT}{function_list} *funcs = virt->lower_module;
{v3_guard}
{INDENT}return {call} ({call_args_concatenated});
}}

'''


def base_function_list(functions):
    base_functions_concatenated = ",\n".join([
        f"{INDENT}base_{function['name']}" for function in functions
        if function["name"] not in EXCLUDE_IN_X
    ])
    return f'''\
CK_X_FUNCTION_LIST p11_virtual_base = {{
{INDENT}{{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */
{base_functions_concatenated}
}};
'''


def format_fixed_function_name(name):
    if name in SHORT_FUNCTIONS:
        return f"short_{name}"
    else:
        return f"fixed ## fixed_index ## _{name}"


def fixed_function(function):
    name = format_fixed_function_name(function["name"])
    arg_indent = " " * len(name + " (")
    args = f", \\\n{arg_indent}".join([
        f"{arg['type']} {arg['name']}"
        for arg in function["arguments"]
    ])
    call = f"funcs->{function['name']}"
    call_indent = " " * len("return " + call + " (")
    call_args_concatenated = f", \\\n{INDENT}{call_indent}".join([
        arg["name"] for arg in function["arguments"]
    ])

    return f'''\
static CK_RV \\
{name} ({args}) \\
{{ \\
{INDENT}CK_FUNCTION_LIST_3_0 *bound; \\
{INDENT}Wrapper *wrapper; \\
{INDENT}CK_X_FUNCTION_LIST *funcs; \\
{INDENT}bound = fixed_closures[fixed_index]; \\
{INDENT}return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \\
{INDENT}wrapper = (Wrapper *) bound; \\
{INDENT}funcs = &wrapper->virt->funcs; \\
{INDENT}return {call} (funcs, \\
{INDENT}{call_indent}{call_args_concatenated}); \\
}} \\
\\
'''


def fixed(functions, closures):
    output = io.StringIO()
    fixed_functions_concatenated = "".join([
        fixed_function(function) for function in functions
        if function["name"] not in EXCLUDE_IN_X
    ])
    output.write(f'''\
#define P11_VIRTUAL_FIXED_FUNCTIONS(fixed_index)        \\
{fixed_functions_concatenated}\
static CK_RV \\
fixed ## fixed_index ## _C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list); \\
\\
static CK_RV \\
fixed ## fixed_index ## _C_GetInterfaceList (CK_INTERFACE_PTR pInterfacesList, \\
                                             CK_ULONG_PTR pulCount); \\
\\
static CK_RV \\
fixed ## fixed_index ## _C_GetInterface (CK_UTF8CHAR_PTR pInterfaceName, \\
                                         CK_VERSION_PTR pVersion, \\
                                         CK_INTERFACE_PTR_PTR ppInterface, \\
                                         CK_FLAGS flags);

#define P11_VIRTUAL_FIXED_GET_FUNCTION_LIST(fixed_index) \\
static CK_RV \\
fixed ## fixed_index ## _C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list) \\
{{ \\
        if (!list) \\
                return CKR_ARGUMENTS_BAD; \\
        *list = (CK_FUNCTION_LIST *)fixed_closures[fixed_index]; \\
        return CKR_OK; \\
}}

#define P11_VIRTUAL_FIXED_GET_INTERFACE_LIST(fixed_index) \\
static CK_RV \\
fixed ## fixed_index ## _C_GetInterfaceList (CK_INTERFACE_PTR pInterfacesList, \\
                                             CK_ULONG_PTR pulCount) \\
{{ \\
        CK_RV rv = CKR_OK; \\
\\
        if (pulCount == NULL_PTR) \\
                return CKR_ARGUMENTS_BAD; \\
\\
        if (pInterfacesList == NULL_PTR) {{ \\
                *pulCount = 1; \\
                return CKR_OK; \\
        }} \\
\\
        if (*pulCount < 1) {{ \\
                *pulCount = 1; \\
                return CKR_BUFFER_TOO_SMALL; \\
        }} \\
\\
        if (rv == CKR_OK) {{ \\
                memcpy (pInterfacesList, \\
                        fixed_interfaces[fixed_index], \\
                        sizeof(CK_INTERFACE)); \\
                *pulCount = 1; \\
        }} \\
\\
        return rv; \\
}}

#define P11_VIRTUAL_FIXED_GET_INTERFACE(fixed_index) \\
static CK_RV \\
fixed ## fixed_index ## _C_GetInterface (CK_UTF8CHAR_PTR pInterfaceName, \\
                                         CK_VERSION_PTR pVersion, \\
                                         CK_INTERFACE_PTR_PTR ppInterface, \\
                                         CK_FLAGS flags) \\
{{ \\
        CK_INTERFACE_PTR interface = fixed_interfaces[fixed_index]; \\
        CK_VERSION_PTR cmp_version = &fixed_closures[fixed_index]->version; \\
\\
        if (ppInterface == NULL_PTR) {{ \\
                return CKR_ARGUMENTS_BAD; \\
        }} \\
\\
        if (pInterfaceName == NULL) {{ \\
                *ppInterface = interface; \\
                return CKR_OK; \\
        }} \\
\\
        if (strcmp ((char *)pInterfaceName, interface->pInterfaceName) != 0 || \\
            (pVersion != NULL && (pVersion->major != cmp_version->major || \\
                                  pVersion->minor != cmp_version->minor)) || \\
            ((flags & interface->flags) != flags)) {{ \\
                return CKR_ARGUMENTS_BAD; \\
        }} \\
        *ppInterface = interface; \\
        return CKR_OK; \\
}}
''')
    functions_concatenated = f", \\\n{INDENT}".join([
        format_fixed_function_name(function["name"]) for function in functions
    ])
    output.write(f'''\
#define P11_VIRTUAL_FIXED_INITIALIZER(fixed_index) \\
{{ \\
        {{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */ \\
{functions_concatenated} \\
}}

''')
    for i in range(closures):
        output.write(f"P11_VIRTUAL_FIXED_FUNCTIONS({i})\n")

    initializers_concatenated = ",\n".join([
        f"{INDENT}P11_VIRTUAL_FIXED_INITIALIZER({i})"
        for i in range(closures)
    ])
    output.write(f'''
CK_FUNCTION_LIST_3_0 p11_virtual_fixed[P11_VIRTUAL_MAX_FIXED] = {{
{initializers_concatenated}
}};

''')
    for i in range(closures):
        output.write(f"""\
P11_VIRTUAL_FIXED_GET_FUNCTION_LIST({i})
P11_VIRTUAL_FIXED_GET_INTERFACE_LIST({i})
P11_VIRTUAL_FIXED_GET_INTERFACE({i})
""")
    return output.getvalue()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffi",
                        action="store_true", help="Generate FFI bindings")
    parser.add_argument("--stack",
                        action="store_true", help="Generate stacked closures")
    parser.add_argument("--base",
                        action="store_true", help="Generate base closures")
    parser.add_argument("--fixed", type=int,
                        help="Generate fixed closures")
    parser.add_argument("infile", type=argparse.FileType("r"))
    parser.add_argument("outfile", type=argparse.FileType("w"))
    args = parser.parse_args()

    functions = json.load(args.infile)["functions"]

    if args.ffi:
        for function in functions:
            if function["name"] in EXCLUDE_IN_X:
                continue
            args.outfile.write(binding_function(function))
        args.outfile.write(binding_info(functions))

    if args.stack:
        for function in functions:
            if function["name"] in EXCLUDE_IN_X:
                continue
            args.outfile.write(stack_function(function))
        args.outfile.write(stack_function_list(functions))

    if args.base:
        for function in functions:
            if function["name"] in EXCLUDE_IN_X:
                continue
            args.outfile.write(base_function(function))
        args.outfile.write(base_function_list(functions))

    if args.fixed is not None:
        args.outfile.write(fixed(functions, args.fixed))
