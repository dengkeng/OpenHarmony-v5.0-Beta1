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

import i18n from '@ohos.i18n'

namespace LanguageUtil {
/**
 * @description 获取系统语言
 * @return string 系统语言ID，如zh-Hans
 */
    export const getSystemLanguage = (): string => {
        return i18n.getSystemLanguage()
    }

    /**
     * @description 获取系统地区
     * @return string 系统地区ID，如：CN
     */
    export const getSystemRegion = (): string => {
        return i18n.getSystemRegion()
    }

    /**
     * 判断是否是中文语言
     * @return boolean
     */
    export function isChineseLanguage(): boolean {
        const language = getSystemLanguage().split('-')[0]
        return language === 'zh'
    }

    /**
     * 判断是否是中文语言，包括中文、藏文、维语
     * @return boolean
     */
    export function isChineseGroupLanguage(): boolean {
        const language = getSystemLanguage().split('-')[0]
        return language === 'zh' || language === 'bo' || language === 'ug'
    }

    /**
     * 判断是否是英文语言
     * @return boolean
     */
    export function isEnglishLanguage(): boolean {
        const language = getSystemLanguage().split('-')[0]
        return language === 'en'
    }
}

export default LanguageUtil