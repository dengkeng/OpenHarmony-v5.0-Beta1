#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2023 Huawei Device Co., Ltd.
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

import enum
from coreImpl.parser import parser
from coreImpl.check import check
from coreImpl.diff import diff


class ToolNameType(enum.Enum):
    COLLECT = 'collect'
    DIFF = 'diff'
    CHECK = 'check'
    COLLECT_H = 'collect_h'
    COLLECT_FILE = 'collect_file'


tool_name_type_set = [
    member.value for name_tool,
    member in ToolNameType.__members__.items()
]


class FormatType(enum.Enum):
    JSON = 'json'
    EXCEL = 'excel'


format_set = [
    member.value for name_format,
    member in FormatType.__members__.items()
]


def run_tools(options):
    tool_name = options.tool_name
    if tool_name == ToolNameType["COLLECT"].value:
        parser.parser(options.parser_path)
    elif tool_name == ToolNameType["DIFF"].value:
        diff.process_dir(options.diff_path_old, options.diff_path_new)
    elif tool_name == ToolNameType['CHECK'].value:
        check.curr_entry(options.parser_path)
    elif tool_name == ToolNameType['COLLECT_H'].value:
        parser.parser_direct(options.parser_path)
    elif tool_name == ToolNameType['COLLECT_FILE'].value:
        parser.parser_file_level(options.output_path)
    else:
        print("工具名称错误")


class Config(object):
    name = 'parser'
    version = '0.1.0'
    description = 'Compare the parser the NDKS'
    commands = [
        {
            "name": "--tool-name",
            "abbr": "-N",
            "required": True,
            "choices": tool_name_type_set,
            "type": str,
            "default": ToolNameType["COLLECT"],
            "help": "工具名称"
        },
        {
            "name": "--parser-path",
            "abbr": "-P",
            "required": True,
            "type": str,
            "help": "解析路径"
        },
        {
            "name": "--diff-path-old",
            "abbr": "-old",
            "required": False,
            "type": str,
            "help": "旧文件路径"
        },
        {
            "name": "--diff-path-new",
            "abbr": "-new",
            "required": False,
            "type": str,
            "help": "新文件路径"
        },
        {
            "name": "--output-path",
            "abbr": "-O",
            "required": False,
            "type": str,
            "help": "collect_file工具输出文件路径"
        }

    ]
