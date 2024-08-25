#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
#
# HDF is dual licensed: you can use it either under the terms of
# the GPL, or the BSD license, at your option.
# See the LICENSE file in the root of this repository for complete details.

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