#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
#

import json
import sys
import CppHeaderParser

if __name__ == "__main__":
    fileName = sys.argv[1];
    try:
        hjson = json.loads(CppHeaderParser.CppHeader(fileName).toJSON())
        print(json.dumps({
            "result": hjson
        }))
    except CppHeaderParser.CppParseError:
        print(CppHeaderParser.CppParseError)
    finally:
        pass