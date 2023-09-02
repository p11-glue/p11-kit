{
    "function_name": "proxy_{function}",
    "function_argument": "{argument_type} {argument_name}",
    "call_lower": "return map.funcs->{function}",
    "call_lower_v3": "return ((CK_FUNCTION_LIST_3_0_PTR)map.funcs)->{function}",
    "call_lower_argument": "{argument_name}",
    "function_body_with_slot": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}State *state = (State *)self;
{indent}Mapping map;
{indent}CK_RV rv;

{indent}rv = map_slot_to_real (state->px, &slotID, &map);
{indent}if (rv != CKR_OK)
{indent}{indent}return rv;
{indent}if (map.funcs->version.major < 3)
{indent}{indent}return CKR_FUNCTION_NOT_SUPPORTED;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "function_body_with_slot_v3": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}State *state = (State *)self;
{indent}Mapping map;
{indent}CK_RV rv;

{indent}rv = map_slot_to_real (state->px, &slotID, &map);
{indent}if (rv != CKR_OK)
{indent}{indent}return rv;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "function_body_with_session_v3": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}State *state = (State *)self;
{indent}Mapping map;
{indent}CK_RV rv;

{indent}rv = map_session_to_real (state->px, &session, &map, NULL);
{indent}if (rv != CKR_OK)
{indent}{indent}return rv;
{indent}if (map.funcs->version.major < 3)
{indent}{indent}return CKR_FUNCTION_NOT_SUPPORTED;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "function_body_with_session": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}State *state = (State *)self;
{indent}Mapping map;
{indent}CK_RV rv;

{indent}rv = map_session_to_real (state->px, &session, &map, NULL);
{indent}if (rv != CKR_OK)
{indent}{indent}return rv;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "function_body_with_session_v3": """\
static CK_RV
{function_name} (CK_X_FUNCTION_LIST *self,
{arglist_indent}{arglist})
{{
{indent}State *state = (State *)self;
{indent}Mapping map;
{indent}CK_RV rv;

{indent}rv = map_session_to_real (state->px, &session, &map, NULL);
{indent}if (rv != CKR_OK)
{indent}{indent}return rv;
{indent}if (map.funcs->version.major < 3)
{indent}{indent}return CKR_FUNCTION_NOT_SUPPORTED;
{indent}{call_lower} ({call_lower_arglist});
}}
    """,
    "entry_argument": "",       # unused
    "entry": "{function_name}",
    "outer": """
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */

{wrappers}

CK_X_FUNCTION_LIST proxy_functions = {{
{indent}{{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }},  /* version */
{xentries}
}};
"""
}
