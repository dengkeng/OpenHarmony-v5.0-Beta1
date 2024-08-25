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

import hilog from '@ohos.hilog'
import AppConfig from '../config/AppConfig'

/**
 * 业务基础日志能力
 */
namespace Logger {

/**
 * 日志级别
 */
    const enum LogVersion {
        Debug = 1,
        Info = 2,
        Warn = 3,
        Error = 4,
        Fatal = 5,
    }

    /**
     * 日志级别, 注意在LogVersion声明之后
     */
    const LOG_LEVEL = LogVersion.Debug

    /**
     * TAG
     */
    const APP_TAG = 'FilePicker'

    /**
     * Service Domain
     */
    const LOG_DOMAIN = 0

    /**
     * 打印 Debug 日志
     * @param tag 日志Tag
     * @param message 打印信息
     */
    export function d(tag: string, message: string): void {
        if (LogVersion.Debug >= LOG_LEVEL) {
            hilog.debug(LOG_DOMAIN, `[${APP_TAG}-${AppConfig.APP_VERSION}]${tag}`, message)
        }
    }

    /**
     * 打印 Info 日志
     * @param tag 日志Tag
     * @param message 打印信息
     */
    export function i(tag: string, message: string): void {
        if (LogVersion.Info >= LOG_LEVEL) {
            hilog.info(LOG_DOMAIN, `[${APP_TAG}-${AppConfig.APP_VERSION}]${tag}`, message)
        }
    }

    /**
     * 打印 Warn 日志
     * @param tag 日志Tag
     * @param message 打印信息
     */
    export function w(tag: string, message: string): void {
        if (LogVersion.Warn >= LOG_LEVEL) {
            hilog.warn(LOG_DOMAIN, `[${APP_TAG}-${AppConfig.APP_VERSION}]${tag}`, message)
        }
    }

    /**
     * 打印 Error 日志
     * @param tag 日志Tag
     * @param message 打印信息
     */
    export function e(tag: string, message: string): void {
        if (LogVersion.Error >= LOG_LEVEL) {
            hilog.error(LOG_DOMAIN, `[${APP_TAG}-${AppConfig.APP_VERSION}]${tag}`, message)
        }
    }
}

export default Logger