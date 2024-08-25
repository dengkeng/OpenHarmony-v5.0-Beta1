/**
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

import { BaseIntent } from '../../common/base/BaseIntent';
import MenuInfo from '../../common/bean/MenuInfo';

export class AutoMenuInitIntent extends BaseIntent {
  public context: Context;

  constructor(context: Context) {
    super();
    this.context = context;
  }

  getIntentTag(): string {
    return 'MenuListInitIntent';
  }
}

export class AutoMenuRefreshIntent extends BaseIntent {
  public context: Context;

  constructor(context: Context) {
    super();
    this.context = context;
  }

  getIntentTag(): string {
    return 'MenuListRefreshIntent';
  }
}

export class AutoMenuClickIntent extends BaseIntent {
  public menuInfo: MenuInfo;

  constructor(menuInfo: MenuInfo) {
    super();
    this.menuInfo = menuInfo;
  }

  getIntentTag(): string {
    return 'MenuClickGoIntent';
  }
}