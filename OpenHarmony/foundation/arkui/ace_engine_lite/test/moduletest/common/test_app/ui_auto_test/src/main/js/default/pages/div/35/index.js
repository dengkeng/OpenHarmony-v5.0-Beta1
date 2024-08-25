/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
import {routePage} from "../../../common/js/general";
export default {
    data: {
        loop:[1, 2, 3],
        flexDirection: "row",
        flexDirectionList: ["row", "column"],
        flexDirectionIndex:1,
        justifyContent: "flex-start",
        justifyContentList: ["flex-start", "center", "flex-end"],
        justifyContentIndex:1,
        alignItems: "flex-start",
        alignItemsList: ["flex-start", "center", "flex-end"],
        alignItemsIndex:1
    },
    ...routePage('pages/div/34/index', 'pages/div/36/index'),
    changeFlexDirection() {
        this.flexDirection = this.flexDirectionList[this.flexDirectionIndex];
        this.flexDirectionIndex = (this.flexDirectionIndex + 1) % 2;
    },
    changeJustifyContent() {
        this.justifyContent = this.justifyContentList[this.justifyContentIndex];
        this.justifyContentIndex = (this.justifyContentIndex + 1) % 3;
    },
    changeAlignItems() {
        this.alignItems = this.alignItemsList[this.alignItemsIndex];
        this.alignItemsIndex = (this.alignItemsIndex + 1) % 3;
    }
}