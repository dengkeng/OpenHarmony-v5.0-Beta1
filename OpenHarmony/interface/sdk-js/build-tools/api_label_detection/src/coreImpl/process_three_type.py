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


from typedef.detection import Output, ErrorMessage, ErrorType
from utils.util import get_position_information, get_js_doc_info
from typedef.process_three_type import get_three_label_value
from utils.constants import label_comparison_dist


def process_struct_type(dict_data: dict, label='default') -> list:
    missing_tag_class_list = judgment_is_default(dict_data, label)
    return missing_tag_class_list


def process_class_type(dict_data: dict, label='default') -> list:
    missing_tag_class_list = judgment_is_default(dict_data, label)
    return missing_tag_class_list


def process_namespace_type(dict_data: dict, label='default') -> list:
    missing_tag_namespace_list = judgment_is_default(dict_data, label)
    return missing_tag_namespace_list


def process_interface_type(dict_data: dict, label='default') -> list:
    missing_tag_interface_list = judgment_is_default(dict_data, label)
    return missing_tag_interface_list


def process_method_type(dict_data: dict, label='default') -> list:
    missing_tag_method_list = judgment_is_default(dict_data, label)
    return missing_tag_method_list


def judgment_is_default(dict_data: dict, label) -> list:
    result_data_total = []
    if 'default' == label:
        result_data_total = default_processing_label(dict_data)
    else:
        if 'Method' == dict_data['apiType']:
            for label_element in label:
                change_label = label_comparison_dist[label_element]
                result_data = process_method_tag(dict_data, change_label)
                result_data_total.extend(result_data)
        else:
            for label_element in label:
                change_label = label_comparison_dist[label_element]
                result_data = process_tag(dict_data, change_label)
                result_data_total.extend(result_data)

    return result_data_total


def process_method_tag(dict_data: dict, label):
    missing_tag_data_list = []
    # 父没，不考虑
    if 'jsDocInfos' not in dict_data:
        return missing_tag_data_list
    parent_information = get_js_doc_info(dict_data['jsDocInfos'])
    if not parent_information:
        return missing_tag_data_list
    process_key = {
        'typeLocations': 'typeLocations',
        'objLocations': 'objLocations'
    }
    if 'params' in dict_data and len(dict_data['params']) > 0:
        # 处理入参
        result_param_list = process_func_param(dict_data, process_key, label, parent_information)
        missing_tag_data_list.extend(result_param_list)
        # 处理出参
    result_return_list = process_func_anonymous_obj(dict_data, process_key, label, parent_information)
    missing_tag_data_list.extend(result_return_list)

    return missing_tag_data_list


def process_func_param(dict_data: dict, key_info: dict, label: str, parent_info):
    message_param_result_list = []
    # 处理每个参数
    for param in dict_data['params']:
        if 'typeLocations' in param and param['typeLocations']:
            result_param_type = process_param_or_return(dict_data, key_info['typeLocations'],
                                                        parent_info, label, param)
            message_param_result_list.extend(result_param_type)
        if 'objLocations' in param and param['objLocations']:
            result_param_obj = process_param_or_return(dict_data, key_info['objLocations'],
                                                       parent_info, label, param)
            message_param_result_list.extend(result_param_obj)

    return message_param_result_list


def process_func_anonymous_obj(dict_data: dict, key_info: dict, label: str, parent_info):
    message_obj_result_list = []
    if 'typeLocations' in dict_data and dict_data['typeLocations']:
        result_return_type = process_param_or_return(dict_data, key_info['typeLocations'], parent_info, label)
        message_obj_result_list.extend(result_return_type)
    if 'objLocations' in dict_data and dict_data['objLocations']:
        result_return_obj = process_param_or_return(dict_data, key_info['objLocations'], parent_info, label)
        message_obj_result_list.extend(result_return_obj)

    return message_obj_result_list


def process_param_or_return(dict_data: dict, key_info: str, parent_info: dict,
                            label, process_data=None) -> list:
    missing_tag_message_list = []
    new_label = label.replace('is', '')
    error_result = {}
    message_of_error = diff_of_param_obj(key_info).split('#')
    if not process_data:
        process_data = dict_data
        message_of_error = diff_of_param_obj(key_info, in_out=1).split('#')
    for child_info in process_data[key_info]:
        # 父有，参or对象没
        if label in parent_info and label in child_info and \
                parent_info[label] and (not child_info[label]):
            error_type = message_of_error[0]
            error_message = message_of_error[1].replace('&', new_label)
            error_result.setdefault('error_type', error_type)
            error_result.setdefault('error_message', error_message)
            message_obj = get_message_obj(dict_data, error_result, process_data)
            missing_tag_message_list.append(message_obj)
            break

    return missing_tag_message_list


def diff_of_param_obj(key, in_out=0):
    diff_data = {
        'typeLocations': '{}#{}'.format(ErrorType.PARAM_NO_TAG.value,
                                        ErrorMessage.METHOD_HAVE_INPUT_PARAM_NO.value),
        'objLocations': '{}#{}'.format(ErrorType.PARAM_OBJ_NO_TAG.value,
                                       ErrorMessage.METHOD_HAVE_PARAM_OBJ_NO.value)
    }
    if 1 == in_out:
        diff_data['typeLocations'] = '{}#{}'.format(ErrorType.RETURN_NO_TAG.value,
                                                    ErrorMessage.METHOD_HAVE_OUTPUT_PARAM_NO.value)
        diff_data['objLocations'] = '{}#{}'.format(ErrorType.RETURN_OBJ_NO_TAG.value,
                                                   ErrorMessage.METHOD_HAVE_RETURN_OBJ_NO.value)
    error_info = ''
    if key in diff_data:
        error_info = diff_data[key]

    return error_info


def process_tag(dict_data: dict, label):
    missing_tag_data_list = []
    if 'childApis' not in dict_data:
        return missing_tag_data_list
    # 处理property
    for child_data in dict_data['childApis']:
        result_list = process_child_quote_of_three(child_data, label)
        missing_tag_data_list.extend(result_list)
    # 节点没有jsDocInfos
    if 'jsDocInfos' not in dict_data:
        error_result = process_no_js_info(dict_data, label)
    else:
        error_result = process_js_info(dict_data, label)
    if error_result:
        message_obj = get_message_obj(dict_data, error_result)
        missing_tag_data_list.append(message_obj)

    return missing_tag_data_list


def process_child_quote_of_three(child_data, label):
    missing_tag_data_list = []
    if 'jsDocInfos' not in child_data:
        return missing_tag_data_list
    child_info = get_js_doc_info(child_data['jsDocInfos'])
    if not child_info:
        return missing_tag_data_list
    if 'typeLocations' in child_data and child_data['typeLocations']:
        process_key = 'typeLocations'
        result_list_of_type = process_reference_type_child(child_data, child_info, label, process_key)
        missing_tag_data_list.extend(result_list_of_type)
    if 'objLocations' in child_data and child_data['objLocations']:
        process_key = 'objLocations'
        result_list_of_obj = process_reference_type_child(child_data, child_info, label, process_key)
        missing_tag_data_list.extend(result_list_of_obj)

    return missing_tag_data_list


def process_reference_type_child(child_data, current_info, label, process_key):
    missing_tag_message_list = []
    new_label = label.replace('is', '')
    for refer_info in child_data[process_key]:
        error_result = {}
        if label in current_info and label in refer_info:
            # property有，引用没
            if current_info[label] and (not refer_info[label]):
                error_result = reference_obj_or_type(process_key, new_label, 1)
                error_result.setdefault('error_quote_name', refer_info.get('typeName'))
            # property没，引用有
            elif (not current_info[label]) and refer_info[label]:
                error_result = reference_obj_or_type(process_key, new_label, 0)
                message_obj = get_message_obj(child_data, error_result)
                missing_tag_message_list.append(message_obj)
                break

        if error_result:
            message_obj = get_message_obj(child_data, error_result)
            missing_tag_message_list.append(message_obj)

    return missing_tag_message_list


def reference_obj_or_type(process_key, new_label, key_num):
    error_result = {}
    error_type = ''
    error_message = ''
    if 'typeLocations' == process_key:
        # property有，引用没
        if 1 == key_num:
            error_type = ErrorType.PROPERTY_REFERENCE_NO_TAG.value
            error_message = ErrorMessage.PROPERTY_HAVE_REFERENCE_NO.value.replace('&', new_label)
        # property没，引用有
        elif 0 == key_num:
            error_type = ErrorType.PROPERTY_NO_TAG.value
            error_message = ErrorMessage.REFERENCE_HAVE_PROPERTY_NO.value.replace('&', new_label)

    elif 'objLocations' == process_key:
        # property有，引用对象没
        if 1 == key_num:
            error_type = ErrorType.PROPERTY_REFERENCE_OBJ_NO_TAG.value
            error_message = ErrorMessage.PROPERTY_HAVE_REFERENCE_OBJ_NO.value.replace('&', new_label)
        # property没，引用对象有
        elif 0 == key_num:
            error_type = ErrorType.PROPERTY_NO_TAG.value
            error_message = ErrorMessage.REFERENCE_OBJ_HAVE_PROPERTY_NO.value.replace('&', new_label)

    error_result.setdefault('error_type', error_type)
    error_result.setdefault('error_message', error_message)

    return error_result


def process_no_js_info(dict_data: dict, label):
    error_result = {}
    new_label = label.replace('is', '')
    for child_data in dict_data['childApis']:
        if 'jsDocInfos' not in child_data:
            continue
        data_tag_info = get_js_doc_info(child_data['jsDocInfos'])
        if not data_tag_info:
            continue
        if label in data_tag_info and data_tag_info[label]:
            error_type = ErrorType.PARENT_NO_TAG.value.replace('$', dict_data['apiType'])
            error_message = (ErrorMessage.METHOD_HAVE_PARENT_NO.value
                             .replace('&', new_label)
                             .replace('$', dict_data['apiType']))
            error_result.setdefault('error_type', error_type)
            error_result.setdefault('error_message', error_message)
            break

    return error_result


def process_js_info(dict_data: dict, label):
    new_label = label.replace('is', '')
    parent_information = get_js_doc_info(dict_data['jsDocInfos'])
    # 对应值是空值
    if not parent_information:
        error_result = process_no_js_info(dict_data, label)
        return error_result
    len_of_dict_data = len(dict_data['childApis'])
    count_label, error_result = judgement_js_info(dict_data, parent_information, label, new_label)
    # 父有，子一个都没有
    if 0 != len_of_dict_data and count_label == len_of_dict_data:
        error_type = ErrorType.CHILD_NO_TAG.value
        error_message = (ErrorMessage.PARENT_HAVE_METHOD_NO.value
                         .replace('$', dict_data['apiType'])
                         .replace('&', new_label))
        error_result.setdefault('error_type', error_type)
        error_result.setdefault('error_message', error_message)

    return error_result


def judgement_js_info(dict_data, parent_information, label, new_label):
    count_label = 0
    error_result = {}
    for child_data in dict_data['childApis']:
        if 'jsDocInfos' not in child_data:
            if parent_information[label]:
                count_label += 1
        else:
            child_tag_infor = get_js_doc_info(child_data['jsDocInfos'])
            if not child_tag_infor:
                count_label += 1
            elif label in parent_information and label in child_tag_infor and \
                    parent_information[label] and child_tag_infor[label]:
                break
            elif label in parent_information and label in child_tag_infor and \
                    parent_information[label] and (not child_tag_infor[label]):
                count_label += 1
                # 父没，子有
            elif label in parent_information and label in child_tag_infor and \
                    (not parent_information[label]) and child_tag_infor[label]:
                error_type = ErrorType.PARENT_NO_TAG.value.replace('$', dict_data['apiType'])
                error_message = (ErrorMessage.METHOD_HAVE_PARENT_NO.value
                                 .replace('$', dict_data['apiType'])
                                 .replace('&', new_label))
                error_result.setdefault('error_type', error_type)
                error_result.setdefault('error_message', error_message)
                break
    return count_label, error_result


def get_message_obj(dict_data: dict, error_result: dict, in_or_out=None) -> Output:
    if not in_or_out:
        defined_text = dict_data['definedText']
    elif in_or_out != dict_data:
        defined_text = in_or_out['definedText']
    else:
        defined_text = dict_data['definedText']
    if error_result.get('error_quote_name'):
        error_message = '({});{}'.format(error_result.get('error_quote_name'),
                                         error_result['error_message'])
    else:
        error_message = error_result['error_message']
    message_obj = Output(dict_data['filePath'], error_result['error_type'], defined_text,
                         get_position_information(dict_data['pos']), error_message)
    return message_obj


def default_processing_label(dict_data: dict):
    missing_tag_total_list = []
    label_dict = get_three_label_value()
    for label in label_dict:
        if 'Method' == dict_data['apiType']:
            result_data = process_method_tag(dict_data, label_dict[label])
        else:
            result_data = process_tag(dict_data, label_dict[label])
        missing_tag_total_list.extend(result_data)

    return missing_tag_total_list


def process_tag_dict(dict_data: dict, label: list):
    # 绑定特定的节点对应标签处理函数
    process_result_list = []
    process_special_tag = {
        'Class': process_class_type,
        'Namespace': process_namespace_type,
        'Interface': process_interface_type,
        'Method': process_method_type,
        'Struct': process_struct_type
    }
    if 'apiType' in dict_data:
        api_type = dict_data['apiType']
        if api_type in process_special_tag:
            process_result = process_special_tag[api_type](dict_data, label)
            process_result_list.extend(process_result)

    return process_result_list
