#!/usr/bin/python

"""
SPDX-License-Identifier: BSD-3-Clause
"""

import sys

INDENT = "        "


def write_fixed_instantiate(output, closures):
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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--closures", type=int,
                        default=64)
    parser.add_argument("--outfile", type=argparse.FileType("w"),
                        default=sys.stdout)
    args = parser.parse_args()
    with args.outfile:
        write_fixed_instantiate(args.outfile, args.closures)
