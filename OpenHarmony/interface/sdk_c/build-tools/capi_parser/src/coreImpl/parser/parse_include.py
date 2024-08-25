#!/usr/bin/env python
# coding=utf-8
##############################################
# Copyright (c) 2021-2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##############################################

import re
import os
import json
import clang.cindex
from clang.cindex import Config
from clang.cindex import Index
from clang.cindex import CursorKind
from clang.cindex import TypeKind
from utils.constants import StringConstant
from utils.constants import RegularExpressions
from typedef.parser.parser import NodeKind


def find_parent(cursor):  # 获取父节点
    cursor_parent = cursor.semantic_parent
    if cursor_parent is not None:
        if cursor_parent.kind == CursorKind.VAR_DECL:  # 父节点为VAR_DECL 用于整型变量节点
            return cursor_parent.kind

        # 用于判断里面成员属于那类
        elif cursor_parent.kind == CursorKind.STRUCT_DECL or cursor_parent.kind == CursorKind.UNION_DECL:
            return cursor_parent.kind
        else:
            parent_kind = processing_root_parent(cursor_parent)
            return parent_kind
    return None


def processing_root_parent(cursor_parent):
    parent = cursor_parent.semantic_parent
    if parent is not None:
        if parent.type.kind == TypeKind.INVALID:
            parent_kind = CursorKind.TRANSLATION_UNIT
            return parent_kind
        else:
            return parent.kind
    return None


def processing_no_child(cursor, data, last_data):  # 处理没有子节点的节点
    if last_data and 'module_name' in last_data:
        data['module_name'] = last_data['module_name']
    if cursor.kind == CursorKind.INTEGER_LITERAL:  # 整型字面量类型节点，没有子节点
        tokens = cursor.get_tokens()
        for token in tokens:
            data["integer_value"] = token.spelling  # 获取整型变量值


def get_token(cursor):
    tokens = []
    for token in cursor.get_tokens():
        tokens.append(token.spelling)

    return tokens


def judgment_extern(cursor, data):  # 判断是否带有extern
    tokens = get_token(cursor)
    if cursor.kind == CursorKind.FUNCTION_DECL:
        if 'static' in tokens or 'deprecated' in tokens:
            is_extern = False
        else:
            is_extern = True
    elif cursor.kind == CursorKind.VAR_DECL:
        if 'extern' in tokens:
            is_extern = True
        else:
            is_extern = False
        if 'const' in tokens:
            data["is_const"] = True
        else:
            data["is_const"] = False
    else:
        is_extern = True

    data["is_extern"] = is_extern


def binary_operator(cursor, data):  # 二元操作符处理
    data["name"] = "binary_ope_no_spelling"
    tokens = cursor.get_tokens()
    spelling_arr = ['<<', '>>', '+', '-', '*', '/']
    for token in tokens:
        if token.spelling in spelling_arr:
            data["operator"] = token.spelling


def distinction_member(cursor, data):  # 区别结构体和联合体成员
    parent_kind = find_parent(cursor)  # 查找父节点类型
    if parent_kind:
        if parent_kind == CursorKind.UNION_DECL:
            data["member"] = "union_member"
        elif parent_kind == CursorKind.STRUCT_DECL:
            data["member"] = "struct_member"


def processing_parm(cursor, data):  # 函数参数节点处理
    if cursor.spelling:  # 函数参数是否带参数名
        data["name"] = cursor.spelling
    else:
        data["name"] = "arg_no_spelling"

    if cursor.type.get_pointee().kind == TypeKind.FUNCTIONPROTO:  # 参数为函数指针，获取对应的返回类型
        data["func_pointer_result_type"] = cursor.type.get_pointee().get_result().spelling


def processing_enum(cursor, data):  # 获取枚举值
    data["value"] = cursor.enum_value


def processing_def(cursor, data):  # 处理宏定义
    data['is_def_func'] = False
    data['name'] = cursor.spelling
    name_len = len(data['name'])
    str1_len = len(data['node_content']['content'])
    text = ''
    if name_len != str1_len:
        if data['node_content']['content']:
            if data['node_content']['content'][name_len] == '(':
                right_index = data['node_content']['content'].index(')')
                param = data['node_content']['content'][name_len:right_index + 1]
                text = data['node_content']['content'][right_index + 1:]
                data['is_def_func'] = True
                data['def_func_name'] = data['name']
                data['def_func_param'] = param
                data['name'] = ''.join(data['name'] + param)
            else:
                text = data['node_content']['content'][name_len:]
        else:
            print('mar_define error, its content is none')
    if text:
        text = text.strip()  # 删除两边的字符（默认是删除左右空格）
        data['text'] = text
    data["type"] = "def_no_type"


def processing_func(cursor, data):  # 处理函数
    data["return_type"] = cursor.result_type.spelling  # 增加返回类型键值对
    judgment_extern(cursor, data)


def processing_type(cursor, data):  # 没有类型的节点处理
    if cursor.kind == CursorKind.MACRO_INSTANTIATION:  # 也属于宏定义 --宏引用
        data["type"] = "insta_no_type"

    elif cursor.kind == CursorKind.INCLUSION_DIRECTIVE:  # 头文件也没type，规定
        data["type"] = "inclusion_no_type"


def processing_name(cursor, data):  # 没有名的节点处理
    if cursor.kind == CursorKind.PAREN_EXPR:  # 括号表达式()
        data["paren"] = "()"
        data["name"] = "paren_expr_no_spelling"

    elif cursor.kind == CursorKind.UNEXPOSED_EXPR:  # 未公开表达式，用于表示未明确定义的表达式
        data["name"] = "unexposed_expr_no_spelling"


def processing_char(cursor, data):  # 字符节点处理
    tokens = list(cursor.get_tokens())
    char_value = (tokens[0].spelling.strip("'"))
    data["name"] = char_value


special_node_process = {
    CursorKind.ENUM_CONSTANT_DECL.name: processing_enum,
    CursorKind.MACRO_DEFINITION.name: processing_def,
    CursorKind.FUNCTION_DECL.name: processing_func,
    CursorKind.VAR_DECL.name: judgment_extern,
    CursorKind.PARM_DECL.name: processing_parm,
    CursorKind.FIELD_DECL.name: distinction_member,
    CursorKind.MACRO_INSTANTIATION.name: processing_type,
    CursorKind.INCLUSION_DIRECTIVE.name: processing_type,
    CursorKind.BINARY_OPERATOR.name: binary_operator,
    CursorKind.PAREN_EXPR.name: processing_name,
    CursorKind.UNEXPOSED_EXPR.name: processing_name,
    CursorKind.CHARACTER_LITERAL.name: processing_char
}


def processing_special_node(cursor, data, key, gn_path=None):  # 处理需要特殊处理的节点
    if key == 0:
        location_path = cursor.spelling
        kind_name = CursorKind.TRANSLATION_UNIT.name
    else:
        location_path = cursor.location.file.name
        kind_name = cursor.kind.name

    loc = {
        "location_path": '{}'.format(location_path),
        "location_line": cursor.location.line,
        "location_column": cursor.location.column
    }
    if gn_path:
        relative_path = os.path.relpath(location_path, gn_path)  # 获取头文件相对路
        loc["location_path"] = relative_path
    data["location"] = loc
    if kind_name in special_node_process.keys():
        node_process = special_node_process[kind_name]
        node_process(cursor, data)  # 调用对应节点处理函数


def node_extent(cursor, current_file):
    start_offset = cursor.extent.start.offset
    end_offset = cursor.extent.end.offset
    with open(current_file, 'r', encoding='utf=8') as f:
        f.seek(start_offset)
        content = f.read(end_offset - start_offset)

    extent = {
        "start_offset": start_offset,
        "end_offset": end_offset,
        "content": content
    }
    f.close()
    return extent


def define_comment(cursor, current_file, data):
    line = cursor.location.line
    with open(current_file, mode='r', encoding='utf-8') as file:
        file_content = file.readlines()[:line]
        file_content = ''.join(file_content)
        pattern = '{} {})'.format(RegularExpressions.DEFINE_COMMENT.value, cursor.spelling)
        matches = re.search(pattern, file_content)
        if matches:
            data['comment'] = matches.group()


def get_default_node_data(cursor, gn_path=None):
    data = {
        "name": cursor.spelling,
        "kind": '',
        "type": cursor.type.spelling,
        "gn_path": gn_path,
        "node_content": {},
        "comment": '',
        "syscap": '',
        "since": '',
        "kit_name": '',
        "sub_system": '',
        "module_name": '',
        "permission": '',
        "class_name": 'global',
        "deprecate_since": '',
        "error_num": 'NA',
        "is_system_api": 'NA',
        "model_constraint": 'NA',
        "cross_platform": 'NA',
        "form": 'NA',
        "atomic_service": 'NA',
        "decorator": 'NA'
    }
    return data


def parser_data_assignment(cursor, current_file, gn_path=None, comment=None, key=0):
    data = get_default_node_data(cursor, gn_path)
    get_comment(cursor, data)
    if key == 0:
        data["kind"] = CursorKind.TRANSLATION_UNIT.name
        if comment:
            data["comment"] = comment
        if gn_path:
            relative_path = os.path.relpath(cursor.spelling, gn_path)
            data["name"] = relative_path
    else:
        content = node_extent(cursor, current_file)
        data["node_content"] = dict(content)
        data["kind"] = cursor.kind.name
        if cursor.kind.name == CursorKind.MACRO_DEFINITION.name:
            define_comment(cursor, current_file, data)
    struct_union_enum = [NodeKind.STRUCT_DECL.value, NodeKind.UNION_DECL.value,
                         NodeKind.ENUM_DECL.value]
    if data.get('kind') in struct_union_enum and 'class_name' in data:
        data['class_name'] = data.get('name')
    get_syscap_value(data)
    get_since_value(data)
    get_kit_value(data)
    get_permission_value(data)
    get_module_name_value(data)
    get_deprecate_since_value(data)
    processing_special_node(cursor, data, key, gn_path)  # 节点处理
    get_file_kit_or_system(data)

    return data


def ast_to_dict(cursor, current_file, last_data, gn_path=None, comment=None, key=0):  # 解析数据的整理
    # 通用赋值
    data = parser_data_assignment(cursor, current_file, gn_path, comment, key)
    if last_data and 'module_name' in last_data:
        data['module_name'] = last_data['module_name']
    children = list(cursor.get_children())  # 判断是否有子节点，有就追加children，没有根据情况来
    if len(children) > 0:
        if key != 0:
            if cursor.kind == CursorKind.FUNCTION_DECL:  # 函数参数
                name = "parm"
            elif (cursor.kind == CursorKind.ENUM_DECL
                  or cursor.kind == CursorKind.STRUCT_DECL
                  or cursor.kind == CursorKind.UNION_DECL):
                name = "members"
            else:
                name = "children"
        else:
            name = "children"
        data[name] = []

        for child in children:
            # 剔除多余宏定义和跳过UNEXPOSED_ATTR节点
            if (child.location.file is not None) and (not child.kind.is_attribute()) \
                    and (child.location.file.name == current_file):
                processing_ast_node(child, current_file, data, name, gn_path)
    else:
        if cursor.kind == CursorKind.FUNCTION_DECL:  # 防止clang默认处理(对于头文件没有的情况)出现没有该键值对
            data["parm"] = []
        processing_no_child(cursor, data, last_data)  # 处理没有子节点的节点
    return data


def get_syscap_value(data: dict):
    syscap_list = []
    if 'none_comment' != data["comment"]:
        pattern = r'@([Ss]yscap).*?(?=\n)'
        matches = re.finditer(pattern, data['comment'], re.DOTALL | re.MULTILINE)
        for mat in matches:
            syscap_list.append(mat.group())
    if len(syscap_list) > 1:
        data["syscap"] = re.sub('@syscap', '', syscap_list[len(syscap_list) - 1], flags=re.IGNORECASE)
    elif 1 == len(syscap_list):
        data["syscap"] = re.sub('@syscap', '', syscap_list[0], flags=re.IGNORECASE)


def get_since_value(data: dict):
    since_list = []
    if 'none_comment' != data["comment"]:
        pattern = r'@(since).*?(?=\n)'
        matches = re.finditer(pattern, data['comment'], re.DOTALL | re.MULTILINE)
        for mat in matches:
            since_list.append(mat.group())
    if len(since_list) > 1:
        data["since"] = since_list[len(since_list) - 1].replace('@since', '')
    elif 1 == len(since_list):
        data["since"] = since_list[0].replace('@since', '')


def get_kit_value(data: dict):
    kit_list = []
    if 'none_comment' != data["comment"]:
        pattern = r'@(kit).*?(?=\n)'
        matches = re.finditer(pattern, data['comment'], re.DOTALL | re.MULTILINE)
        for mat in matches:
            kit_list.append(mat.group())
    if len(kit_list) > 1:
        data["kit_name"] = kit_list[len(kit_list) - 1].replace('@kit', '')
    elif 1 == len(kit_list):
        data["kit_name"] = kit_list[0].replace('@kit', '')


def get_module_name_value(data: dict):
    module_name_list = []
    if 'none_comment' != data["comment"]:
        pattern = r'@(addtogroup).*?(?=\n)'
        matches = re.finditer(pattern, data['comment'], re.DOTALL | re.MULTILINE)
        for mat in matches:
            module_name_list.append(mat.group())
    if len(module_name_list) > 1:
        data["module_name"] = module_name_list[len(module_name_list) - 1].replace('@addtogroup', '')
    elif 1 == len(module_name_list):
        data["module_name"] = module_name_list[0].replace('@addtogroup', '')


def get_permission_value(data: dict):
    permission_list = []
    if 'none_comment' != data["comment"]:
        pattern = r'@(permission).*?(?=\n)'
        matches = re.finditer(pattern, data['comment'], re.DOTALL | re.MULTILINE)
        for mat in matches:
            permission_list.append(mat.group())
    if len(permission_list) > 1:
        data["permission"] = permission_list[len(permission_list) - 1].replace('@permission', '')
    elif 1 == len(permission_list):
        data["permission"] = permission_list[0].replace('@permission', '')


def get_deprecate_since_value(data: dict):
    deprecate_list = []
    if 'none_comment' != data["comment"]:
        pattern = r'@(deprecated).*?(?=\n)'
        matches = re.finditer(pattern, data['comment'], re.DOTALL | re.MULTILINE)
        for mat in matches:
            deprecate_list.append(mat.group())
    if len(deprecate_list) > 1:
        data["deprecate_since"] = (deprecate_list[len(deprecate_list) - 1].replace('@deprecated', '')
                                   .replace('since', ''))
    elif 1 == len(deprecate_list):
        data["deprecate_since"] = (deprecate_list[0].replace('@deprecated', '')
                                   .replace('since', ''))


def get_file_kit_or_system(node_data):
    current_file = os.path.dirname(__file__)
    kit_json_file_path = os.path.abspath(os.path.join(current_file,
                                                      r"kit_sub_system/c_file_kit_sub_system.json"))
    if 'kit_name' in node_data and 'sub_system' in node_data and \
            (not node_data['kit_name'] or not node_data['sub_system']):
        relative_path = node_data.get('location').get('location_path').replace('\\', '/')
        kit_name, sub_system = get_kit_system_data(kit_json_file_path, relative_path)
        if not node_data['kit_name']:
            node_data['kit_name'] = kit_name
        if not node_data['sub_system']:
            node_data['sub_system'] = sub_system


def get_kit_system_data(json_path, relative_path):
    kit_name = ''
    sub_system_name = ''
    with open(json_path, 'r', encoding='utf-8') as fs:
        kit_system_data = json.load(fs)
        for data in kit_system_data['data']:
            if 'filePath' in data and relative_path in data['filePath']:
                kit_name = data['kitName']
                sub_system_name = data['subSystem']
                break
    return kit_name, sub_system_name


def get_comment(cursor, data: dict):
    if cursor.raw_comment:  # 是否有注释信息，有就取，没有过
        data["comment"] = cursor.raw_comment
    else:
        data["comment"] = 'none_comment'


def processing_ast_node(child, current_file, data, name, gn_path):
    child_data = ast_to_dict(child, current_file, data, gn_path, key=1)
    if child.kind == CursorKind.TYPE_REF:
        data["type_ref"] = child_data
    else:
        data[name].append(child_data)


def preorder_travers_ast(cursor, total, comment, current_file, gn_path=None):  # 获取属性
    previous_data = {}
    ast_dict = ast_to_dict(cursor, current_file, previous_data, gn_path, comment)  # 获取节点属性
    total.append(ast_dict)  # 追加到数据统计列表里面


def get_start_comments(include_path):  # 获取每个头文件的最开始注释
    file_comment = []
    content = open_file(include_path)
    if content:
        pattern = RegularExpressions.START_COMMENT.value
        matches = re.finditer(pattern, content, re.DOTALL | re.MULTILINE)
        for mat in matches:
            file_comment.append(mat.group())

    with open(include_path, 'r', encoding='utf-8') as f:
        f.seek(0)
        content = f.read()
        pattern_high = RegularExpressions.END_COMMENT.value
        matches_high = re.findall(pattern_high, content, re.DOTALL | re.MULTILINE)
        if matches_high:
            file_comment.extend(matches_high)
        f.close()
    str_file_comment = '\n'.join(file_comment)
    return str_file_comment


def open_file(include_path):
    with open(include_path, 'r', encoding='utf-8') as f:
        content = ''
        mark = 0
        if 'ffrt' in include_path:
            end_line_mark = r'#ifndef'
        else:
            end_line_mark = r'#endif'
        for line in f:
            if line.startswith(end_line_mark):
                mark = 1
                break
            else:
                inside_ifdef = True

            if inside_ifdef:
                content += line
        if mark == 0:
            content = ''
        f.close()
        return content


def api_entrance(share_lib, include_path, gn_path=None, link_path=None):  # 统计入口
    # clang.cindex需要用到libclang.dll共享库   所以配置共享库
    if Config.loaded:
        print("config.loaded == true")
    else:
        Config.set_library_file(share_lib)
        print("lib.dll: install path")
    # 创建AST索引
    index = Index.create()
    print('=' * 50)
    # options赋值为如下，代表宏定义解析数据也要
    args = ['-I{}'.format(path) for path in link_path]
    args.append('-std=c99')
    options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD

    data_total = []  # 列表对象-用于统计
    for item in include_path:  # 对每个头文件做处理
        tu = index.parse(item, args=args, options=options)
        print(tu)
        print('=' * 50)
        ast_root_node = tu.cursor  # 获取根节点
        print(ast_root_node)
        matches = get_start_comments(item)  # 接收文件最开始的注释
        # 前序遍历AST
        preorder_travers_ast(ast_root_node, data_total, matches, item, gn_path)  # 调用处理函数
        print('=' * 50)

    return data_total


def get_include_file(include_file_path, link_path, gn_path=None):  # 库路径、.h文件路径、链接头文件路径
    # libclang.dll库路径
    libclang_path = StringConstant.LIB_CLG_PATH.value
    # c头文件的路径
    file_path = include_file_path
    print(file_path)
    # 头文件链接路径
    link_include_path = link_path  # 可以通过列表传入
    data = api_entrance(libclang_path, file_path, gn_path, link_include_path)  # 调用接口
    return data
