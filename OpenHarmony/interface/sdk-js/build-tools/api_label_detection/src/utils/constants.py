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


mutex_label_dist = {
    'isAtomicService': ['deprecatedVersion', 'isSystemApi']
}


one_to_many_function = ['off', 'on', 'emit', 'once']


label_name_dist = {
    'isAtomicService': '@atomicservice',
    'deprecatedVersion': '@deprecated',
    'isSystemApi': '@systemapi',
    'isForm': '@form',
    'isCrossPlatForm': '@crossplatform'
}


label_comparison_dist = {
    'atomicservice': 'isAtomicService',
    'form': 'isForm',
    'crossplatform': 'isCrossPlatForm'
}


contrast_function = {
    'add': 'remove',
    'increase': 'decrease',
    'open': 'close',
    'begin': 'end',
    'insert': 'delete',
    'show': 'hide',
    'create': 'destroy',
    'lock': 'unlock',
    'source': 'target',
    'first': 'last',
    'min': 'max',
    'start': 'stop',
    'get': 'set',
    'next': 'previous',
    'up': 'down',
    'new': 'old',
    'on': 'off',
    'once': 'emit',

    "remove": "add",
    "decrease": "increase",
    "close": "open",
    "end": "begin",
    "delete": "insert",
    "hide": "show",
    "destroy": "create",
    "unlock": "lock",
    "target": "source",
    "last": "first",
    "max": "min",
    "stop": "start",
    "set": "get",
    "previous": "next",
    "down": "up",
    "old": "new",
    "off": "on",
    "emit": "once"
}
