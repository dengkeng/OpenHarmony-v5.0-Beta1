/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class ArkResourcesHelper {
    static COLOR: number = 10001
    static FLOAT: number = 10002

    static $r(id: string) {
        var splitted = id.split(".", 2);
        var strType = splitted[1]
        var type = undefined;
        switch (strType) {
            case 'float':
                type = ArkResourcesHelper.FLOAT;
                break;
            case 'color':
            default:
                type = ArkResourcesHelper.COLOR;
                break;
        }
        return { "id": -1, "type": type, 'params': [id], 'bundleName': '', 'moduleName': '' };
    }
}