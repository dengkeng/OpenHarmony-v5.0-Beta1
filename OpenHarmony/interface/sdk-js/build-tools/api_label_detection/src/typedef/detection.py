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

import enum


class Output:
    file_path = ''
    error_type = ''
    defined_text = ''
    position = ''
    error_info = ''

    def __init__(self, file_path, error_type, defined_text, position, error_info):
        self.file_path = file_path
        self.error_type = error_type
        self.defined_text = defined_text
        self.position = position
        self.error_info = error_info


class ErrorMessage(enum.Enum):
    MUTEX_LABEL = 'In the same API, [$] tag and [&] tag are mutually exclusive'
    RELATIVE_LABEL = 'Functions that appear in pairs,[$] function missing [&] tag'
    ENUM_VALUE_LABEL = ('The enumeration type [$] is labeled with [&], but none of the enumeration '
                        'values are labeled with this label')
    ENUM_LABEL = ('The enumeration type [$] is not marked with [&], '
                  'but the enumeration value is marked with this label')
    PARENT_HAVE_METHOD_NO = '[$] has a [&] label, but none of its methods have a [&] label'
    METHOD_HAVE_PARENT_NO = '[$]does not have [&] label，but the methods below it has [&] label'
    METHOD_HAVE_INPUT_PARAM_NO = 'functions have [&] label, but the param do not have [&] label'
    METHOD_HAVE_OUTPUT_PARAM_NO = 'functions have [&] label, but the return value do not have [&] label'
    METHOD_HAVE_PARAM_OBJ_NO = 'functions have [&] label, but the argument anonymous object do not have [&] label'
    METHOD_HAVE_RETURN_OBJ_NO = 'functions have [&] label, but the return anonymous objects do not have [&] label'
    PROPERTY_HAVE_REFERENCE_NO = 'property have [&] label, but the reference of property do not have [&] label'
    REFERENCE_HAVE_PROPERTY_NO = 'reference of property have [&] label, but the property do not have [&] label'
    PROPERTY_HAVE_REFERENCE_OBJ_NO = 'property have [&] label, but the reference_obj of property do not have [&] label'
    REFERENCE_OBJ_HAVE_PROPERTY_NO = 'reference_obj of property have [&] label, but the property do not have [&] label'


class ErrorType(enum.Enum):
    MUTEX_LABEL = 'mutex_label'
    ENUM_LABEL = 'enum_missing_label'
    ENUM_VALUE_LABEL = 'enum_value_missing_label'
    RELATIVE_LABEL = 'paired_function_omission_label'
    PARENT_NO_TAG = '$_missing_label'
    CHILD_NO_TAG = 'method_missing_label'
    PARAM_NO_TAG = 'param_missing_label'
    RETURN_NO_TAG = 'return_missing_label'
    PARAM_OBJ_NO_TAG = 'param_anonymous_object_missing_label'
    RETURN_OBJ_NO_TAG = 'return_anonymous_object_missing_label'
    PROPERTY_NO_TAG = 'property_missing_label'
    PROPERTY_REFERENCE_NO_TAG = 'property_of_reference_missing_label'
    PROPERTY_REFERENCE_OBJ_NO_TAG = 'property_of_reference_obj_missing_label'
