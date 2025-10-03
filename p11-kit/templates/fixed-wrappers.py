{
    "function_name": "fixed ## fixed_index ## _{function}",
    "function_name_short": "short_{function}",
    "function_argument": "{argument_type} {argument_name}",
    "call_lower": "return funcs->{function}",
    "call_lower_argument": "{argument_name}",
    "function_body": """\
static CK_RV \\
{function_name} ({arglist}) \\
{{ \\
{indent}CK_FUNCTION_LIST_3_2 *bound; \\
{indent}Wrapper *wrapper; \\
{indent}CK_X_FUNCTION_LIST *funcs; \\
{indent}bound = fixed_closures[fixed_index]; \\
{indent}return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \\
{indent}wrapper = (Wrapper *) bound; \\
{indent}funcs = &wrapper->virt->funcs; \\
{indent}{call_lower} (funcs, \\
{call_lower_arglist_indent}{call_lower_arglist}); \\
}} \\
""",
    "entry_argument": "",
    "entry": "{function_name}",
    "outer": """
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */

#define P11_VIRTUAL_FIXED_FUNCTIONS(fixed_index)        \\
{wrappers}\
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

#define P11_VIRTUAL_FIXED_INITIALIZER(fixed_index) \\
{{ \\
{indent}{{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */ \\
{entries} \\
}}
"""
}
