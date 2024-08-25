/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 * @file: Button group configuration file
 */

import ImagePathConst from '../constant/ImagePathConst';

const firstBtns = [
  {
    type: 'record',
    iconDisableUrl: 'ic_public_recording_Grey',
    iconDefaultUrl: 'ic_public_recording_',
    iconActiveUrl: 'soundEnabled',
    isDisable: true,
    isActive: false,
    iconText: ''
  },
  {
    type: 'keep',
    iconDisableUrl: 'ic_public_pause_Grey',
    iconDefaultUrl: 'ic_public_pause',
    iconActiveUrl: 'ic_public_pause_Enabled',
    isDisable: false,
    isActive: false,
    iconText: ''
  },
  {
    type: 'add',
    iconDisableUrl: 'ic_public_add_filled_Grey',
    iconDefaultUrl: 'ic_public_add_filled',
    iconActiveUrl: '',
    isDisable: false,
    isActive: false,
    iconText: ''
  },
  {
    type: 'video',
    iconDisableUrl: 'ic_public_video_Grey',
    iconDefaultUrl: 'ic_public_video',
    iconActiveUrl: 'ic_public_video_filled',
    isDisable: true,
    isActive: false,
    iconText: ''
  },
  {
    type: 'mute',
    iconDisableUrl: 'ic_public_voice_Grey',
    iconDefaultUrl: 'ic_public_voice',
    iconActiveUrl: 'ic_public_voice_Enabled',
    isDisable: true,
    isActive: false,
    iconText: ''
  },
  {
    type: 'contact',
    iconDisableUrl: 'ic_public_contacts_Grey',
    iconDefaultUrl: 'ic_public_contacts',
    iconActiveUrl: '',
    isDisable: false,
    isActive: false,
    iconText: ''
  }
];

const secondBtns = [
  {
    type: 'exchange',
    iconDisableUrl: 'ic_public_shuffle_Grey',
    iconDefaultUrl: 'ic_public_shuffle',
    iconActiveUrl: 'ic_public_shuffle_Enabled',
    isDisable: false,
    isActive: false,
    iconText: ''
  },
  {
    type: 'merge',
    iconDisableUrl: 'ic_merge_Grey',
    iconDefaultUrl: 'ic_merge',
    iconActiveUrl: 'ic_merge_Enabled',
    isDisable: true,
    isActive: false,
    iconText: ''
  }
];

/**
 * Process the image text of the button group
 *
 * @param {Array} arr - Pass in an array
 */
function addIconUrl(arr) {
  const regExp = /^icon.*.*Url$/;
  arr.forEach((item) => {
    for (let key in item) {
      if (Object.prototype.hasOwnProperty.call(item, key) && regExp.test(key)) {
        item[key] = `${ImagePathConst.BASE_URL}${item[key]}.svg`;
      }
    }
  });
}

addIconUrl(firstBtns);
addIconUrl(secondBtns);

export const btnGroupList = firstBtns;
export const threePartyList = secondBtns;

const btnGroupConfig = {
  btnGroupList,
  threePartyList
}
export default btnGroupConfig;