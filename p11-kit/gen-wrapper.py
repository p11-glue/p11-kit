#!/usr/bin/python3

import re
import string
import typing

# Parsing
#
# Parse PKCS#11 headers in ../common and obtain the list of normalized
# function prototypes represented as Function.

P11_FUNCTION_RE = re.compile(
    r'\A_CK_DECLARE_FUNCTION\s*\(C_(\w+), \((.*)\)\);')
P11_ARGUMENT_RE = re.compile(r'\s*([^,]+\s+\**)([^, ]+)')
P11_FUNCTION_LIST_MEMBER_RE = re.compile(r'\A\s*CK_C_(\S+)\s+.*;')

P11_X_FUNCTION_RE = re.compile(
    r'\Atypedef CK_RV \(\* CK_X_(\w+)\)\s*\((.*)\);')
P11_X_ARGUMENT_RE = re.compile(r'\s*([^,]+)')
P11_X_FUNCTION_LIST_MEMBER_RE = re.compile(r'\A\s*CK_X_(\S+)\s+.*;')

Argument = typing.NamedTuple('Argument',
                             [('name', str),
                              ('type', str)])
Function = typing.NamedTuple('Function',
                             [('name', str),
                              ('args', [Argument])])


class Parser(object):
    def __init__(self):
        self.__function_lines = list()
        self.__x_function_lines = list()
        self.__function_names = list()
        self.__x_function_names = list()
        self.__args = dict()
        self.__x_args = dict()
        self.functions = list()
        self.x_functions = list()

    def __read_pkcs11_h(self, infile):
        reading_list = False
        while True:
            l = infile.readline()
            if not l:
                break
            if l.startswith('_CK_DECLARE_FUNCTION'):
                line = l.strip()
                while not line.endswith(';'):
                    l = infile.readline()
                    if not l:
                        break
                    line += ' ' + l.strip()
                self.__function_lines.append(line)
                continue
            elif l.startswith('struct ck_function_list'):
                if not l.endswith(';'):
                    reading_list = True
                continue
            elif reading_list:
                match = P11_FUNCTION_LIST_MEMBER_RE.match(l)
                if match:
                    self.__function_names.append(match.group(1))
                continue
            else:
                continue
            break

    def __read_pkcs11i_h(self, infile):
        reading_list = False
        while True:
            l = infile.readline()
            if not l:
                break
            if l.startswith('typedef CK_RV (* CK_X_'):
                line = l.strip()
                while not line.endswith(';'):
                    l = infile.readline()
                    if not l:
                        break
                    line += ' ' + l.strip()
                self.__x_function_lines.append(line)
                continue
            elif l.startswith('struct _CK_X_FUNCTION_LIST'):
                if not l.endswith(';'):
                    reading_list = True
                continue
            elif reading_list:
                match = P11_X_FUNCTION_LIST_MEMBER_RE.match(l)
                if match:
                    self.__x_function_names.append(match.group(1))
                continue
            else:
                continue
            break

    def __parse_function_line(self, line):
        match = P11_FUNCTION_RE.match(line)
        (name, args) = (match.group(1), match.group(2))
        args = [Argument(arg.group(2), arg.group(1).strip())
                for arg in P11_ARGUMENT_RE.finditer(args)]
        return Function(name, args)

    def __parse_function_lines(self):
        for line in self.__function_lines:
            function = self.__parse_function_line(line)
            self.__args[function.name] = function.args
            self.functions.append(function)
        self.functions.sort(key=lambda x: self.__function_names.index(x.name))

    def __parse_x_function_line(self, line):
        match = P11_X_FUNCTION_RE.match(line)
        (name, args) = (match.group(1), match.group(2))
        args = [Argument('', arg.group(1).strip())
                for arg in P11_X_ARGUMENT_RE.finditer(args)]
        return Function(name, args)

    def __parse_x_function_lines(self):
        for line in self.__x_function_lines:
            function = self.__parse_x_function_line(line)
            self.__x_args[function.name] = function.args
            self.x_functions.append(function)
        self.x_functions.sort(
            key=lambda x: self.__x_function_names.index(x.name))

    def parse(self, pkcs11_h, pkcs11i_h):
        self.__read_pkcs11_h(pkcs11_h)
        self.__read_pkcs11i_h(pkcs11i_h)
        self.__parse_function_lines()
        self.__parse_x_function_lines()
        for function in self.functions:
            args = self.__x_args.get(function.name)
            if args:
                for index, arg in enumerate(args[1:]):
                    old = function.args[index]
                    function.args[index] = Argument(old.name, arg.type)
        for function in self.x_functions:
            old = function.args[0]
            function.args[0] = Argument('self', old.type)
            args = self.__args.get(function.name)
            if args:
                for index, arg in enumerate(args):
                    old = function.args[index+1]
                    function.args[index+1] = Argument(arg.name, old.type)

# Code generation
#
# The code generation logic relies on string.Template().  That means,
# the input file embeds Python expressions in ${...} fragments.
#
# The entry point of the template is the FileTemplate class.

P11_INDENT_RE = re.compile(r' {8}')

P11_SHORT_FUNCTIONS = {
    'GetFunctionStatus': 'short_C_GetFunctionStatus',
    'CancelFunction': 'short_C_CancelFunction'
}

# Known mapping between PKCS#11 types and FFI types, except *_PTR.
P11_FFI_TYPES = {
    'CK_NOTIFY': '&ffi_type_pointer',
    'CK_BYTE': '&ffi_type_uchar',
    'CK_BBOOL': '&ffi_type_uchar',
    'CK_SLOT_ID': '&ffi_type_ulong',
    'CK_MECHANISM_TYPE': '&ffi_type_ulong',
    'CK_ULONG': '&ffi_type_ulong',
    'CK_SESSION_HANDLE': '&ffi_type_ulong',
    'CK_FLAGS': '&ffi_type_ulong',
    'CK_OBJECT_HANDLE': '&ffi_type_ulong',
    'CK_USER_TYPE': '&ffi_type_ulong'
}


def type_to_ffi_type(p11_type):
    if p11_type.endswith('_PTR'):
        return '&ffi_type_pointer'
    ffi_type = P11_FFI_TYPES.get(p11_type)
    if ffi_type:
        return ffi_type
    raise RuntimeError('unknown pkcs11 type %s' % p11_type)


def format_type(type):
    if not type.endswith('*') and not type.endswith(' '):
        return type + ' '
    return type


class Template(object):
    def __init__(self, template):
        self.__template = string.Template(template)

    def __getitem__(self, name):
        if hasattr(self, name):
            return getattr(self, name)

    def substitute(self, **kwargs):
        self.substitute_kwargs = kwargs
        return self.__template.substitute(self, **kwargs)


class FunctionTemplate(Template):
    @property
    def function_name(self):
        function = self.substitute_kwargs['function']
        return function.name

    def indent_for_arglist(self):
        name = self.substitute_kwargs['wrapper_function_name']
        prefix = '{function} ('.format(function=name)
        return P11_INDENT_RE.sub('\t', (len(prefix) * ' '))

    def format_arglist(self, args, sep=',\n'):
        indent = self.indent_for_arglist()
        l = ['{type}{name}'.format(type=format_type(arg.type),
                                   name=arg.name)
             for arg in args]
        separator = '{separator}{indent}'.format(separator=sep,
                                                 indent=indent)
        return separator.join(l).strip()

    @property
    def arglist(self):
        function = self.substitute_kwargs['function']
        return self.format_arglist(function.args)

    def format_args(self, args, sep=', '):
        l = [arg.name for arg in args]
        return sep.join(l)

    @property
    def args(self):
        function = self.substitute_kwargs['function']
        return self.format_args(function.args)

    @property
    def args2(self):
        function = self.substitute_kwargs['function']
        return self.format_args(function.args[1:])


class FunctionListTemplate(Template):
    def __init__(self, template, function_template):
        self.function_template = function_template
        super(FunctionListTemplate, self).__init__(template)

    def excluded_functions(self):
        return list()

    def wrapper_function_name(self, function):
        raise NotImplementedError

    @property
    def function_list(self):
        result = list()
        parser = self.substitute_kwargs['parser']
        for function in parser.functions:
            if function.name in self.excluded_functions():
                continue
            s = self.function_template.substitute(
                function=function,
                wrapper_function_name=self.wrapper_function_name(function))
            result.append(s)
        return '\n'.join(result)

    @property
    def x_function_list(self):
        result = list()
        parser = self.substitute_kwargs['parser']
        for function in parser.x_functions:
            if function.name in self.excluded_functions():
                continue
            s = self.function_template.substitute(
                function=function,
                wrapper_function_name=self.wrapper_function_name(function))
            result.append(s)
        return '\n'.join(result)

    @property
    def initializer_list(self):
        result = list()
        parser = self.substitute_kwargs['parser']
        for function in parser.functions:
            if function.name in self.excluded_functions():
                continue
            result.append('\t' + self.wrapper_function_name(function))
        return ',\n'.join(result)

    @property
    def x_initializer_list(self):
        result = list()
        parser = self.substitute_kwargs['parser']
        for function in parser.x_functions:
            if function.name in self.excluded_functions():
                continue
            result.append('\t' + self.wrapper_function_name(function))
        return ',\n'.join(result)


class BaseFunctionTemplate(FunctionTemplate):
    def __init__(self):
        super(BaseFunctionTemplate, self).__init__('''\
static CK_RV
${wrapper_function_name} (${arglist})
{
        p11_virtual *virt = (p11_virtual *)self;
        CK_FUNCTION_LIST *funcs = virt->lower_module;
        return funcs->C_${function_name} (${args2});
}
''')


class BaseFunctionListTemplate(FunctionListTemplate):
    def __init__(self):
        super(BaseFunctionListTemplate, self).__init__(
            '''\
${x_function_list}

CK_X_FUNCTION_LIST p11_virtual_base = {
        { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
${x_initializer_list}
};
''',
            BaseFunctionTemplate())

    def wrapper_function_name(self, function):
        return 'base_C_{function}'.format(function=function.name)


class StackFunctionTemplate(FunctionTemplate):
    def __init__(self):
        super(StackFunctionTemplate, self).__init__('''\
static CK_RV
${wrapper_function_name} (${arglist})
{
        p11_virtual *virt = (p11_virtual *)self;
        CK_X_FUNCTION_LIST *funcs = virt->lower_module;
        return funcs->C_${function_name} (funcs, ${args2});
}
''')


class StackFunctionListTemplate(FunctionListTemplate):
    def __init__(self):
        super(StackFunctionListTemplate, self).__init__(
            '''\
${x_function_list}

CK_X_FUNCTION_LIST p11_virtual_stack = {
        { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
${x_initializer_list}
};
''',
            StackFunctionTemplate())

    def wrapper_function_name(self, function):
        return 'stack_C_{function}'.format(function=function.name)


class BindingFunctionTemplate(FunctionTemplate):
    def __init__(self):
        super(BindingFunctionTemplate, self).__init__('''\
static void
${wrapper_function_name} (${arglist})
{
        *ret = funcs->C_${function_name} (funcs,
${args});
}
''')

    @property
    def arglist(self):
        args = [Argument('cif', 'ffi_cif *'),
                Argument('ret', 'CK_RV *'),
                Argument('args[]', 'void *'),
                Argument('funcs', 'CK_X_FUNCTION_LIST *')]
        return self.format_arglist(args)

    def indent_for_args(self):
        function = self.substitute_kwargs['function']
        prefix = '        *ret = funcs->C_{function} ('.format(
            function=function.name)
        return P11_INDENT_RE.sub('\t', (len(prefix) * ' '))

    def format_args(self, args, sep=',\n'):
        l = ['*({type}*)args[{index}]'.format(type=format_type(arg.type),
                                              index=index)
             for index, arg in enumerate(args)]
        indent = self.indent_for_args()
        separator = '{separator}{indent}'.format(separator=sep,
                                                 indent=indent)
        return indent + separator.join(l).strip()

    @property
    def args(self):
        function = self.substitute_kwargs['function']
        return self.format_args(function.args[1:])


class BindingFunctionListTemplate(FunctionListTemplate):
    def __init__(self):
        super(BindingFunctionListTemplate, self).__init__(
            '''\
${x_function_list}
''',
            BindingFunctionTemplate())

    def wrapper_function_name(self, function):
        return 'binding_C_{function}'.format(function=function.name)


class MaxFunctionsTemplate(Template):
    def __init__(self):
        super(MaxFunctionsTemplate, self).__init__('${max_functions}')

    @property
    def max_functions(self):
        parser = self.substitute_kwargs['parser']
        return str(len(parser.functions))


class MaxArgsTemplate(Template):
    def __init__(self):
        super(MaxArgsTemplate, self).__init__('${max_args}')

    @property
    def max_args(self):
        parser = self.substitute_kwargs['parser']
        return str(max([len(function.args)
                        for function in parser.functions]))


class FunctionInfoTemplate(FunctionTemplate):
    def __init__(self):
        super(FunctionInfoTemplate, self).__init__('''\
        { FUNCTION (${function_name}), { ${args}, NULL } },\
''')

    def format_args(self, args, sep=', '):
        l = [type_to_ffi_type(arg.type) for arg in args]
        return sep.join(l).strip()


class FunctionInfoListTemplate(FunctionListTemplate):
    def __init__(self):
        super(FunctionInfoListTemplate, self).__init__(
            '''\
static const FunctionInfo function_info[] = {
${function_list}
        { 0, }
};
''',
            FunctionInfoTemplate())

    def excluded_functions(self):
        return ['GetFunctionList'] + list(P11_SHORT_FUNCTIONS)

    def wrapper_function_name(self, function):
        return function.name


class FileTemplate(Template):
    def __init__(self, infile):
        super(FileTemplate, self).__init__(infile.read())

    @property
    def base_function_list(self):
        template = BaseFunctionListTemplate()
        return template.substitute(**self.substitute_kwargs)

    @property
    def stack_function_list(self):
        template = StackFunctionListTemplate()
        return template.substitute(**self.substitute_kwargs)

    @property
    def binding_function_list(self):
        template = BindingFunctionListTemplate()
        return template.substitute(**self.substitute_kwargs)

    @property
    def max_functions(self):
        template = MaxFunctionsTemplate()
        return template.substitute(**self.substitute_kwargs)

    @property
    def max_args(self):
        template = MaxArgsTemplate()
        return template.substitute(**self.substitute_kwargs)

    @property
    def function_info_list(self):
        template = FunctionInfoListTemplate()
        return template.substitute(**self.substitute_kwargs)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='gen-wrapper')
    parser.add_argument('template', type=argparse.FileType('r'),
                        help='template file')
    parser.add_argument('pkcs11', type=argparse.FileType('r'),
                        help='the pkcs11.h header file')
    parser.add_argument('pkcs11i', type=argparse.FileType('r'),
                        help='the pkcs11i.h header file')
    args = parser.parse_args()

    parser = Parser()
    parser.parse(args.pkcs11, args.pkcs11i)
    template = FileTemplate(args.template)
    print(template.substitute(parser=parser))
