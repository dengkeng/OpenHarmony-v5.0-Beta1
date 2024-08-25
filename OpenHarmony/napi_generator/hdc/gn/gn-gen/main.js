/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
*
* http://www.apache.org/licenses/LICENSE-2.0 
*
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License. 
*/
const path = require("path");
const stdio = require("stdio");
const { AnalyzeCMake } = require("./src/analyze_cmake");
const { AnalyzeMake } = require("./src/analyze_make");
const { GenerateGn } = require("./src/generate_gn");
const { Logger } = require("./src/logger");
const { Tool } = require("./src/tool");

if (process.execPath.endsWith("node") || process.execPath.endsWith("node.exe")) {
    Tool.CURRENT_TOOL_PATH = __dirname;//工具目录，用来找到res内资源
}
else {
    Tool.CURRENT_TOOL_PATH = path.parse(process.execPath).dir;
}

if (Tool.MOCK_TYPE == Tool.MOCK_ENUM.MOCK_RUN) {
    GenerateGn.mockGenerate();//通过mock数据运行
}

let ops = stdio.getopt({
    'type': { key: 't', args: 1, description: "", default: "cmake" },
    'filename': {
        key: 'f', args: 1,
        description: "The make file's relative path \
( third_party/opencv/CMakeLists.txt , make file can be Makefile/CMakeLists.txt)"
    },
    'ohos_product_output': {
        key: 'o', args: 1, description: "ohos product output relative path",
        default: "out/rk3568"
    },
    'ohos_project_path': { key: 'p', args: 1, description: "ohos project path ( /home/xxx/ohos_project )" },
    'cmake_args': { key: 'a', args: 1, description: "like: (-DABC,-DQWE)", default: "" },
    'subsystem_name': { key: 's', args: 1, description: "subsystem", default: "test_subsystem" },
    'part_name': { key: 'm', args: 1, description: "part", default: "test_part" },
    'porting_to': { key: 'd', args: 1, description: "porting to", default: "" },
});

Tool.OHOS_PROJECT_PATH = ops.ohos_project_path;

Tool.OHOS_PORTING_TO = ops.porting_to;

Tool.OHOS_PRODUCT_OUTPUT_PATH = ops.ohos_product_output;

Tool.OHOS_SUBSYSTEM_NAME = ops.subsystem_name;
Tool.OHOS_PART_NAME = ops.part_name;

//需要对参数做一些正确性判断

let compileFile = path.parse(path.join(Tool.OHOS_PROJECT_PATH, ops.filename));

if (ops.type == "cmake") {//cmake
    AnalyzeCMake.analyze(compileFile, ops.cmake_args.substring(1, ops.cmake_args.length - 1));
}
else if (ops.type == "make") {//make
    AnalyzeMake.analyze(compileFile);
}
else {
    Logger.err("not support " + ops.filename);
}
