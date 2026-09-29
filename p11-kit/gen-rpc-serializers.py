#!/usr/bin/python

"""
Generate the CK_MECHANISM parameter serializers used by rpc-message.c.

A mechanism parameter struct in pkcs11.json qualifies for a generated
encoder/decoder pair when each of its members is either a scalar, an inline
array, or a pointer that can be paired with the member holding its length
by name, following the PKCS#11 pFoo/ulFooLen convention.  Structs that do
not qualify - because they embed another struct, point at one, or have a
pointer whose length lives in a differently named member - are ignored;
they still need a hand-written serializer in rpc-message.c.

Which mechanisms actually use which serializer is not decided here.  That
is the p11_rpc_mechanism_serializers table in rpc-message.c, which is
hand-written on purpose: it is the wire format, and it should not change
just because a struct appeared in a new header.  We do insist that the
decision gets made, though: a struct that qualifies must either be used by
that table or be listed in the excludes file, otherwise this script fails.
So when a new parameter struct shows up in pkcs11.h, somebody has to say
whether it goes on the wire.

SPDX-License-Identifier: BSD-3-Clause
"""

import ast
import json
import re
import sys

class SpecError (Exception):
    pass


TAB_WIDTH = 8
INDENT = "\t"

# Structs worth generating a mechanism parameter serializer for.
CANDIDATE_RE = re.compile (r"(_PARAMS[0-9]*|_CONTEXT)$")

ARRAY_RE = re.compile (r"^unsigned char\[[0-9]+\]$")

# Pointers to bytes.  Anything else that points somewhere needs a
# hand-written serializer, so it is left unclassified below.
POINTER_TYPES = {
    "unsigned char *",
    "CK_BYTE_PTR",
    "CK_CHAR_PTR",
    "CK_UTF8CHAR_PTR",
    "CK_VOID_PTR",
}

# Names the length of a pFoo member may go by.
LENGTH_SUFFIXES = ("Len", "Length", "Count", "Size")

# Neither scalars nor anything we can serialize.
OPAQUE_TYPES = {
    "CK_CREATEMUTEX",
    "CK_DESTROYMUTEX",
    "CK_LOCKMUTEX",
    "CK_UNLOCKMUTEX",
    "__builtin_ms_va_list",
}


def align (column):
    """Indent up to a column, the way the hand-written code does it."""

    return "\t" * (column // TAB_WIDTH) + " " * (column % TAB_WIDTH)


def indent_width (indent):
    return len (indent.replace ("\t", " " * TAB_WIDTH))


def classify (type, structs):
    """Map a member type onto a wire kind, or None if we cannot tell."""

    if type == "long unsigned int":
        return "ulong"
    # The only plain bytes in a parameter struct are flags; normalising
    # them to 0/1 keeps CK_TRUE and CK_FALSE meaningful across the wire.
    if type == "unsigned char":
        return "bool"
    if ARRAY_RE.match (type):
        return "fixed-array"
    if type in POINTER_TYPES:
        return "pointer"
    if type in structs or type in OPAQUE_TYPES:
        return None
    if type.endswith ("*") or type.endswith ("_PTR"):
        return None
    if type.startswith ("CK_C_"):
        return None
    # Everything else spelled CK_something is a CK_ULONG typedef.  If that
    # ever stops being true the generated code will not compile.
    if type.startswith ("CK_"):
        return "ulong"
    return None


def length_member (pointer, members, structs):
    """Find the member holding the length of a pFoo pointer, if any."""

    base = pointer[1:] if re.match (r"^p[A-Z_]", pointer) else pointer
    wanted = {f"ul{base}{suffix}".lower () for suffix in LENGTH_SUFFIXES}

    for member, type in members.items ():
        if member.lower () in wanted and classify (type, structs) == "ulong":
            return member

    return None


def derive_fields (members, structs):
    """Work out the wire format of a struct, or None if it is ambiguous."""

    kinds = {}
    for member, type in members.items ():
        kind = classify (type, structs)
        if kind is None:
            return None
        kinds[member] = kind

    # Pair every pointer with the member holding its length first, so that
    # the pair goes on the wire where the earlier of the two sits.  Struct
    # declarations are not consistent about which comes first.
    lengths = {}
    for member, kind in kinds.items ():
        if kind != "pointer":
            continue
        length = length_member (member, members, structs)
        if length is None or length in lengths:
            return None
        lengths[length] = member

    fields = []
    paired = set ()
    for member in members:
        if member in paired:
            continue
        if kinds[member] == "pointer":
            pointer, length = member, length_member (member, members, structs)
        elif member in lengths:
            pointer, length = lengths[member], member
        else:
            fields.append ({"kind": kinds[member], "name": member})
            continue
        paired.update ((pointer, length))
        fields.append ({"kind": "byte-array", "name": pointer,
                        "length": length})

    return fields


def serializer_name (struct):
    return struct[len ("CK_"):].lower ()


def field_values (field):
    """Names of the decoder temporaries holding a field's wire value."""

    member = field["name"]
    if field["kind"] == "ulong":
        return f"val_{member}", None
    if field["kind"] == "bool":
        return f"byte_{member}", None
    return f"data_{member}", f"len_{member}"


def emit_encoder_body (struct, fields, templates):
    body = templates["encode_prologue"].format (
        indent=INDENT,
        struct=struct,
    )

    for field in fields:
        kind = field["kind"]
        member = field["name"]

        if kind in ("ulong", "bool"):
            body += templates[f"encode_{kind}"].format (
                indent=INDENT,
                member=member,
            )
        else:
            key = "encode_byte_array" if kind == "byte-array" \
                else "encode_fixed_array"
            call = "p11_rpc_buffer_add_byte_array ("
            body += templates[key].format (
                indent=INDENT,
                cont=align (indent_width (INDENT) + len (call)),
                member=member,
                length=field.get ("length"),
            )

    return body


def emit_decoder_body (struct, fields, templates):
    body = ""
    reads = []

    for field in fields:
        key = "ulong" if field["kind"] == "ulong" \
            else "byte" if field["kind"] == "bool" \
            else "byte_array"
        value, length = field_values (field)
        body += templates[f"decode_declare_{key}"].format (
            indent=INDENT,
            value=value,
            length=length,
        )
        reads.append (templates[f"decode_read_{key}"].format (
            value=value,
            length=length,
        ))

    body += templates["decode_read"].format (
        indent=INDENT,
        reads=f" ||\n{align (indent_width (INDENT) + len ('if ('))}".join (reads),
    )

    body += templates["decode_prologue"].format (
        indent=INDENT,
        struct=struct,
    )

    for field in fields:
        kind = field["kind"]
        value, length = field_values (field)
        key = {
            "bool": "decode_assign_bool",
            "byte-array": "decode_assign_byte_array",
            "fixed-array": "decode_assign_fixed_array",
        }.get (kind, "decode_assign")

        body += templates[key].format (
            indent=INDENT,
            member=field["name"],
            length=field.get ("length"),
            value=value,
            length_value=length,
        )

    body += templates["decode_epilogue"].format (
        indent=INDENT,
        struct=struct,
    )

    return body


def emit_serializer (struct, fields, templates):
    name = serializer_name (struct)
    encoder_name = templates["encoder_name"].format (name=name)
    decoder_name = templates["decoder_name"].format (name=name)

    return templates["encoder"].format (
        encoder_name=encoder_name,
        cont=align (len (f"{encoder_name} (")),
        body=emit_encoder_body (struct, fields, templates),
    ) + "\n" + templates["decoder"].format (
        decoder_name=decoder_name,
        cont=align (len (f"{decoder_name} (")),
        body=emit_decoder_body (struct, fields, templates),
    )


def read_excludes (file):
    """Struct names the maintainer has decided to keep off the wire."""

    if file is None:
        return set ()

    return {
        line.split ("#")[0].strip () for line in file
        if line.split ("#")[0].strip ()
    }


def read_used (file, templates):
    """Serializers named by the tables in rpc-message.c."""

    pattern = re.escape (templates["encoder_name"]).replace (
        r"\{name\}", r"([a-z0-9_]+)")

    return set (re.findall (pattern, file.read ()))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser ()
    parser.add_argument ("--template", required=True,
                         type=argparse.FileType ("r"))
    parser.add_argument ("--excludes", type=argparse.FileType ("r"))
    parser.add_argument ("--used-by", required=True,
                         type=argparse.FileType ("r"),
                         help="C source holding the serializer tables")
    parser.add_argument ("--infile", required=True,
                         type=argparse.FileType ("r"))
    parser.add_argument ("--outfile", type=argparse.FileType ("w"),
                         default=sys.stdout)
    args = parser.parse_args ()

    templates = ast.literal_eval (args.template.read ())
    excludes = read_excludes (args.excludes)
    used = read_used (args.used_by, templates)
    structs = {
        struct["name"]: {
            member["name"]: member["type"] for member in struct["members"]
        }
        for struct in json.load (args.infile)["structs"]
    }

    derivable = {}
    for struct in sorted (structs):
        if not CANDIDATE_RE.search (struct):
            continue
        fields = derive_fields (structs[struct], structs)
        if fields is not None:
            derivable[struct] = fields

    try:
        stale = excludes - set (derivable)
        if stale:
            raise SpecError (f"{args.excludes.name} lists "
                             f"{', '.join (sorted (stale))}, which "
                             f"{'has' if len (stale) == 1 else 'have'} no "
                             f"derivable wire format to exclude; drop "
                             f"{'it' if len (stale) == 1 else 'them'}")

        serializers = []
        for struct, fields in derivable.items ():
            name = serializer_name (struct)
            if name in used:
                if struct in excludes:
                    raise SpecError (f"{struct} is excluded but "
                                     f"{args.used_by.name} uses its "
                                     f"serializer; drop it from "
                                     f"{args.excludes.name}")
                serializers.append (emit_serializer (struct, fields,
                                                     templates))
            elif struct not in excludes:
                raise SpecError (
                    f"nothing uses a serializer for {struct}.  Either put it "
                    f"on the wire, by adding an entry to "
                    f"p11_rpc_mechanism_serializers in {args.used_by.name} "
                    f"naming "
                    f"{templates['encoder_name'].format (name=name)} and "
                    f"{templates['decoder_name'].format (name=name)}, or "
                    f"keep it off the wire by adding {struct} to "
                    f"{args.excludes.name}")
    except SpecError as ex:
        sys.exit (f"{parser.prog}: {ex}")

    with args.outfile:
        args.outfile.write (templates["outer"].format (
            serializers="\n".join (serializers),
        ))
