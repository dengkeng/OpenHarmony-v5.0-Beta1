#!/bin/bash
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

WORK_SPACE=$(cd `dirname $0`; pwd)

OHOS_GLUE_DIR=${WORK_SPACE}/ohos_glue
INTERFACE_DIR=${WORK_SPACE}/ohos_interface

INTERFACE_INCLUDE_DIR=${INTERFACE_DIR}/include
INTERFACE_OHOS_GLUE_DIR=${INTERFACE_DIR}/ohos_glue

CLANG_FORMAT_DIR=${WORK_SPACE}/../../../prebuilts/clang/ohos/linux-x86_64/llvm/bin

copy_files() {
  echo "begin to copy ohos interface files"

  cp ${INTERFACE_INCLUDE_DIR}/ohos_nweb/* ${WORK_SPACE}/ohos_nweb/include

  rm -rf ${WORK_SPACE}/ohos_adapter/interfaces
  cp -rf ${INTERFACE_INCLUDE_DIR}/ohos_adapter ${WORK_SPACE}/ohos_adapter/interfaces
}

translate_files() {
  echo "begin to translate ohos glue code"

  rm -rf ${OHOS_GLUE_DIR}/scripts
  cp -rf ${INTERFACE_OHOS_GLUE_DIR}/scripts ${OHOS_GLUE_DIR}

  python3 ${OHOS_GLUE_DIR}/scripts/translator.py webview
}

copy_files

file_list=`find ${OHOS_GLUE_DIR} -type f \( -name "*.h" -o -name "*.cpp" \)`
for file in $file_list
do
  ${CLANG_FORMAT_DIR}/clang-format -style=file -i $file
done

