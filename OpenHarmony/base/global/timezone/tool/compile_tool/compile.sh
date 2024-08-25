#!/bin/bash
# Copyright (c) 2022 Huawei Device Co., Ltd.
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
set -e
script_path=$(cd $(dirname $0);pwd)
iana_path="${script_path}/../../data/iana"
posix_path="${iana_path}/../prebuild/posix"
zic_path="${iana_path}/../prebuild/tool/linux"

make -C ${iana_path}
mv ${iana_path}/zic ${zic_path}

state_name=('africa' 'antarctica' 'asia' 'australasia' 'europe' 'etcetera' 'northamerica' 'southamerica' 'backward')
for name in ${state_name[@]}
do
    ${zic_path}/zic -d ${iana_path}/zoneinfo ${iana_path}/$name
done

rm -rf ${posix_path}/*
mv ${iana_path}/zoneinfo/* ${posix_path}
mv ${iana_path}/version.txt ${posix_path}
echo 'done'
exit 0