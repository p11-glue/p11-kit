#!/usr/bin/python

"""
SPDX-License-Identifier: BSD-3-Clause
"""

import ast
import json
import sys

INDENT = "        "
X_EXCLUDES = [
    "C_GetFunctionList",
    "C_GetFunctionStatus",
    "C_CancelFunction",
    "C_GetInterfaceList",
    "C_GetInterface",
]


def emit_wrapper_function(function, templates, concat_lines=False):
    arglist_separator = ", \\\n" if concat_lines else ",\n"

    function_name = templates["function_name"].format(
        function=function["name"],
    )
    arglist_indent = " " * len(f"{function_name} (")
    arglist = f"{arglist_separator}{arglist_indent}".join([
        templates["function_argument"].format(
            argument_index=index,
            argument_name=argument["name"],
            argument_type=argument["type"],
        )
        for index, argument in enumerate(function["arguments"])
    ])

    call_lower_template = templates["call_lower"]
    if function["version"] >= 3:
        call_lower_template = templates.get("call_lower_v3",
                                            call_lower_template)

    call_lower = call_lower_template.format(
        function=function["name"],
    )
    call_lower_arglist_indent = " " * len(f"{INDENT}{call_lower} (")
    call_lower_arglist = f"{arglist_separator}{call_lower_arglist_indent}".join([
        templates["call_lower_argument"].format(
            argument_index=index,
            argument_name=argument["name"],
            argument_type=argument["type"],
        )
        for index, argument in enumerate(function["arguments"])
    ])

    has_slot_id = next((argument for argument in function["arguments"] if argument["type"] == "CK_SLOT_ID"), None)
    has_session_handle = next((argument for argument in function["arguments"] if argument["type"] == "CK_SESSION_HANDLE"), None)
    assert not (has_slot_id and has_session_handle)

    function_body_template = templates.get("function_body")
    if function_body_template and function["version"] >= 3:
        function_body_template = templates.get("function_body_v3",
                                               function_body_template)

    if has_slot_id:
        template = templates.get("function_body_with_slot")
        if template is not None:
            function_body_template = templates.get(
                "function_body_with_slot_v3",
                template,
            )
    elif has_session_handle:
        template = templates.get("function_body_with_session")
        if template is not None:
            function_body_template = templates.get(
                "function_body_with_session_v3",
                template,
            )

    return function_body_template.format(
        indent=INDENT,
        function_name=function_name,
        arglist=arglist,
        arglist_indent=arglist_indent,
        call_lower=call_lower,
        call_lower_arglist=call_lower_arglist,
        call_lower_arglist_indent=call_lower_arglist_indent,
    )


def emit_wrapper_entry(function, templates, suffix=None):
    if suffix is not None:
        template_name = f"function_name_{suffix}"
    else:
        template_name = "function_name"

    function_name = templates[template_name].format(
        function=function["name"],
    )

    entry_arglist = ", ".join([
        templates["entry_argument"].format(
            argument_ffi_type=argument["ffi-type"],
        )
        for argument in function["arguments"]
    ])

    return templates["entry"].format(
        function_name=function_name,
        entry_arglist=entry_arglist,
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True,
                        type=argparse.FileType("r"))
    parser.add_argument("--concat-lines", action="store_true")
    parser.add_argument("--excludes", type=argparse.FileType("r"))
    parser.add_argument("--renames", nargs="*")
    parser.add_argument("--infile", required=True,
                        type=argparse.FileType("r"))
    parser.add_argument("--outfile", type=argparse.FileType("w"),
                        default=sys.stdout)
    args = parser.parse_args()

    functions = json.load(args.infile)["functions"]
    templates = ast.literal_eval(args.template.read())

    excludes = []
    if args.excludes:
        excludes.extend(args.excludes.read().split())

    renames = {}
    if args.renames:
        renames.update({k: v for k, v in [r.split(":") for r in args.renames]})

    separator = "\\\n" if args.concat_lines else "\n"
    wrappers = separator.join([
        emit_wrapper_function(
            function,
            templates,
            args.concat_lines,
        )
        for function in functions if function["name"] not in excludes
    ])

    separator = ", \\\n" if args.concat_lines else ",\n"
    xentries = separator.join([
        INDENT + emit_wrapper_entry(
            function,
            templates,
            renames.get(function["name"]),
        )
        for function in functions if function["name"] not in X_EXCLUDES
    ])
    entries = separator.join([
        INDENT + emit_wrapper_entry(
            function,
            templates,
            renames.get(function["name"]),
        )
        for function in functions
    ])

    args.outfile.write(templates["outer"].format(
        indent=INDENT,
        wrappers=wrappers,
        xentries=xentries,
        entries=entries,
    ))
