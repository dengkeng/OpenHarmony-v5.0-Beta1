/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

/**
 * 错误码常量
 */
namespace ErrorCodeConst {
/**
 * 使用静默登录接口时帐号未登录场景
 */
    export const ACCOUNT_NOT_LOGIN = 2002

    /**
     * FILE_ACCESS相关接口错误码
     */
    export enum FILE_ACCESS {
        /**
         * 文件名已存在
         */
        FILE_NAME_EXIST = 13900015, // 新错误码13900015
        /**
         * 文件名非法，包含非法字符或过长
         */
        FILE_NAME_INVALID = 14000001, // 新错误码14000001
        /**
         * IPC异常
         */
        IPC_ERROR = -102825984,
        /**
         * 媒体库查询为空errcode返回3
         */
        GET_MEDIAFILE_NULL = '3'
    }

    /**
     * 选择器对外返回的错误码
     */
    export enum PICKER {
        /**
         * 创建文件：同名文件已存在
         */
        FILE_NAME_EXIST = 1001,
        /**
         * 创建文件：文件名非法
         */
        FILE_NAME_INVALID = 1002,
        /**
         * uri授权失败
         */
        GRANT_URI_PERMISSION_FAIL = 2001,
        /**
         * 其他未知错误
         */
        OTHER_ERROR = 9001,
        /**
         * 创建正常
         */
        NORMAL = 1000
    }
}

export default ErrorCodeConst