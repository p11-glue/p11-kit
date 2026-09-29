{
    "encoder_name": "p11_rpc_buffer_add_{name}_mechanism_value",
    "decoder_name": "p11_rpc_buffer_get_{name}_mechanism_value",

    "encoder": """\
static void
{encoder_name} (p11_buffer *buffer,
{cont}const void *value,
{cont}CK_ULONG value_length)
{{
{body}}}
""",
    "decoder": """\
static bool
{decoder_name} (p11_buffer *buffer,
{cont}size_t *offset,
{cont}void *value,
{cont}CK_ULONG *value_length)
{{
{body}}}
""",

    "encode_prologue": """\
{indent}{struct} params;

{indent}/* Check if value can be converted to {struct}. */
{indent}if (value_length != sizeof ({struct})) {{
{indent}{indent}p11_buffer_fail (buffer);
{indent}{indent}return;
{indent}}}

{indent}memcpy (&params, value, value_length);

""",
    "encode_ulong": "{indent}p11_rpc_buffer_add_uint64 (buffer, params.{member});\n",
    "encode_bool": "{indent}p11_rpc_buffer_add_byte (buffer, params.{member} ? 1 : 0);\n",
    "encode_byte_array": """\
{indent}p11_rpc_buffer_add_byte_array (buffer, (unsigned char *)params.{member},
{cont}params.{length});
""",
    "encode_fixed_array": """\
{indent}p11_rpc_buffer_add_byte_array (buffer, (unsigned char *)params.{member},
{cont}sizeof (params.{member}));
""",

    "decode_declare_ulong": "{indent}uint64_t {value};\n",
    "decode_declare_byte": "{indent}unsigned char {value};\n",
    "decode_declare_byte_array": """\
{indent}const unsigned char *{value};
{indent}size_t {length};
""",
    "decode_read_ulong": "!p11_rpc_buffer_get_uint64 (buffer, offset, &{value})",
    "decode_read_byte": "!p11_rpc_buffer_get_byte (buffer, offset, &{value})",
    "decode_read_byte_array": "!p11_rpc_buffer_get_byte_array (buffer, offset, &{value}, &{length})",
    "decode_read": """
{indent}if ({reads})
{indent}{indent}return false;
""",

    "decode_prologue": """
{indent}if (value) {{
{indent}{indent}{struct} params = {{ 0 }};

""",
    "decode_assign": "{indent}{indent}params.{member} = {value};\n",
    "decode_assign_bool": "{indent}{indent}params.{member} = {value} ? CK_TRUE : CK_FALSE;\n",
    "decode_assign_byte_array": """\
{indent}{indent}params.{member} = (void *) {value};
{indent}{indent}params.{length} = {length_value};
""",
    "decode_assign_fixed_array": """
{indent}{indent}if ({length_value} != sizeof (params.{member}))
{indent}{indent}{indent}return false;

{indent}{indent}memcpy (params.{member}, {value}, sizeof (params.{member}));
""",
    "decode_epilogue": """
{indent}{indent}memcpy (value, &params, sizeof ({struct}));
{indent}}}

{indent}if (value_length)
{indent}{indent}*value_length = sizeof ({struct});

{indent}return true;
""",

    "outer": """\
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */

{serializers}\
""",
}
