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

import zipfile
import os
import re
import openpyxl as op
from typedef.compare import Output, DoesItExist


output_result_list = []


def unzip(folder_path):
    # 获取文件夹中所有的 zip 文件
    zip_files = [f for f in os.listdir(folder_path) if f.endswith('.zip')]

    # 遍历每个 zip 文件并解压到目标文件夹
    for zip_file in zip_files:
        with zipfile.ZipFile(os.path.join(folder_path, zip_file), 'r') as zip_ref:
            zip_ref.extractall(path=folder_path)


def generate_excel(output_file_path):
    data = []
    for output_result in output_result_list:
        info_data = []
        info_data.append(output_result.platform)
        info_data.append(output_result.file_path)
        info_data.append(output_result.old_is_exist)
        info_data.append(output_result.new_is_exist)
        data.append(info_data)
    wb = op.Workbook()
    ws = wb['Sheet']
    ws.append(['序号', '平台', '文件路径', '旧版本是否存在', '新版本是否存在'])
    number = 1
    for title in data:
        d = number, title[0], title[1], title[2], title[3]
        ws.append(d)
        number += 1
    wb.save(output_file_path)


def do_diff(old_dir, new_dir, system_type):
    old_file_list = os.listdir(old_dir)
    new_file_list = os.listdir(new_dir)
    diff_list(old_file_list, new_file_list, old_dir, new_dir, system_type)


def diff_list(old_file_list, new_file_list, old_dir, new_dir, system_type):
    all_list = set(old_file_list + new_file_list)
    if len(all_list) == 0:
        return
    for target_file in all_list:
        if (target_file in old_file_list
                and target_file not in new_file_list):
            diff_file_path = os.path.join(old_dir, target_file)
            del_old_file(diff_file_path, system_type)
        elif (target_file in new_file_list
                and target_file not in old_file_list):
            diff_file_path = os.path.join(new_dir, target_file)
            add_new_file(diff_file_path, system_type)
        else:
            # 同时存在的文件夹
            if os.path.isdir(os.path.join(new_dir, target_file)):
                do_diff(os.path.join(old_dir, target_file), os.path.join(new_dir, target_file), system_type)
            # 同时存在的文件
            else:
                target_path = extract_file_path(os.path.join(new_dir, target_file))
                out_put = Output(system_type, target_path, DoesItExist.EXIST.value, DoesItExist.EXIST.value)
                output_result_list.append(out_put)


def add_new_file(diff_file_path, system_type):
    if os.path.isdir(diff_file_path):
        add_file(diff_file_path, system_type)
    else:
        target_path = extract_file_path(diff_file_path)
        out_put = Output(system_type, target_path, DoesItExist.ABSENT.value, DoesItExist.EXIST.value)
        output_result_list.append(out_put)


def del_old_file(diff_file_path, system_type):
    if os.path.isdir(diff_file_path):
        del_file(diff_file_path, system_type)
    else:
        target_path = extract_file_path(diff_file_path)
        out_put = Output(system_type, target_path, DoesItExist.EXIST.value, DoesItExist.ABSENT.value)
        output_result_list.append(out_put)


def del_file(dir_path, system_type):
    file_list = os.listdir(dir_path)
    for file in file_list:
        file_path = os.path.join(dir_path, file)
        if os.path.isdir(file_path):
            del_file(file_path, system_type)
        else:
            target_path = extract_file_path(file_path)
            out_put = Output(system_type, target_path, DoesItExist.EXIST.value, DoesItExist.ABSENT.value)
            output_result_list.append(out_put)


def add_file(dir_path, system_type):
    file_list = os.listdir(dir_path)
    for file in file_list:
        file_path = os.path.join(dir_path, file)
        if os.path.isdir(file_path):
            add_file(file_path, system_type)
        else:
            target_path = extract_file_path(file_path)
            out_put = Output(system_type, target_path, DoesItExist.ABSENT.value, DoesItExist.EXIST.value)
            output_result_list.append(out_put)


def extract_file_path(file_path):
    if len(file_path) == 0:
        return ''
    pattern = re.compile("ohos-sdk(.*)")
    result = re.search(pattern, file_path).group(0)
    return result


def start_do_diff(old_file_path, new_file_path, output_file_path):
    old_platform = os.path.basename(old_file_path)
    system_type = old_platform
    unzip(old_file_path)
    unzip(new_file_path)
    do_diff(old_file_path, new_file_path, system_type)
    # 输出Excel
    if os.path.isdir(output_file_path):
        output_file_path = os.path.join(output_file_path, 'diff.xlsx')
    generate_excel(output_file_path)
