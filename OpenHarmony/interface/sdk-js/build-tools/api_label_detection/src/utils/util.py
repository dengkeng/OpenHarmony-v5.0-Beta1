#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2024 Huawei Device Co., Ltd.
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

import json
import re
import openpyxl as op
from utils.constants import label_comparison_dist


def get_start_characters(target_character):
    pattern = r'([a-z]*)'

    match = re.search(pattern, target_character)
    if match:
        return match.group()[:match.end()]
    else:
        return ''


# 剩余字符
def get_remaining_characters(start_character, target_character):
    return target_character[target_character.index(start_character) + len(start_character):]


def json_file_data(file_path):  # json文件转为dict数据
    with open(file_path, 'r', encoding='utf-8') as file:
        dict_data = json.load(file)
        file.close()

    return dict_data


def label_type_conversion(tagged_value):
    if tagged_value == '':
        return False
    if tagged_value == '-1':
        return False
    if not tagged_value:
        return False
    return True


def get_check_labels(doc_info: dict, label_list):
    if len(doc_info) > 0:
        result = {}
        for label in label_list:
            result[label_comparison_dist.get(label)] = doc_info[label_comparison_dist.get(label)]
        return result
    else:
        return {}


def generate_excel(result_info_list: list, output_address):
    data = []
    for diff_info in result_info_list:
        info_data = [diff_info.file_path, diff_info.error_type, diff_info.defined_text, diff_info.position,
                     diff_info.error_info]
        data.append(info_data)
    wb = op.Workbook()
    ws = wb['Sheet']
    ws.append(['文件路径', '错标类型', 'api信息', '位置信息', '漏标详情'])
    for title in data:
        d = title[0], title[1], title[2], title[3], title[4]
        ws.append(d)
    wb.save(output_address)


def get_position_information(pos: dict):
    return 'line: ' + str(pos['line']) + ', character: ' + str(pos['character'])


def set_label_to_result(message, label, mutex_label):
    return message.replace('$', label).replace('&', mutex_label)


def get_js_doc_info(js_doc_info_list: list):
    if len(js_doc_info_list) > 0:
        return js_doc_info_list[len(js_doc_info_list) - 1]
    return None

