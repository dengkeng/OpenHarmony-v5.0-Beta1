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

import { ProcessResult } from '../../common/base/BaseViewModel';
import { BaseViewModel } from '../../common/base/BaseViewModel';
import { BaseIntent } from '../../common/base/BaseIntent';
import MenuInfo from '../../common/bean/MenuInfo';
import { AutoMenuClickIntent, AutoMenuInitIntent, AutoMenuRefreshIntent } from './AutoMenuIntent';
import { AutoMenuModel } from './AutoMenuModel';
import { AutoMenuViewState } from './AutoMenuViewState';
import Logger from '../../common/utils/Logger';

const TAG = 'AutoMenu';
const DISPLAY_MODEL_LIST = 'list';
const DISPLAY_MODEL_CARD = 'card';

export class AutoMenuViewModel extends BaseViewModel<AutoMenuModel, AutoMenuViewState> {
  protected initModel(): AutoMenuModel {
    return new AutoMenuModel();
  }

  protected initViewState(): AutoMenuViewState {
    return new AutoMenuViewState();
  }

  protected async processIntentWithModel(intents: BaseIntent, model: AutoMenuModel,
    viewStat: AutoMenuViewState): Promise<ProcessResult> {
    Logger.info(TAG, 'start processIntentWithModel: ' + intents.getIntentTag());
    if (intents instanceof AutoMenuInitIntent) {
      let menuInfoList: MenuInfo[] = await model.getMenuInfoListFromRdb(intents.context);
      viewStat.listMenuList = menuInfoList.filter((item) => {
        return (DISPLAY_MODEL_LIST === item.displayedMode || DISPLAY_MODEL_CARD === item.displayedMode)
      })
      return ProcessResult.SUCCESS;
    }
    if (intents instanceof AutoMenuRefreshIntent) {
      let menuInfoList: MenuInfo[] = await model.getMenuInfoListFromBms(intents.context);
      viewStat.listMenuList = menuInfoList.filter((item) => {
        return (DISPLAY_MODEL_LIST === item.displayedMode || DISPLAY_MODEL_CARD === item.displayedMode)
      })
      Logger.info(TAG, 'AutoMenuRefreshIntent: ' + JSON.stringify(menuInfoList));
      Logger.info(TAG, 'viewState: ' + JSON.stringify(viewStat));
      return ProcessResult.SUCCESS;
    }
    if (intents instanceof AutoMenuClickIntent) {
      model.handleMenuClick(intents.menuInfo);
      return ProcessResult.SUCCESS;
    }
    Logger.error(TAG, 'undefined intents: ' + intents.getIntentTag());
    return ProcessResult.FAIL;
  }
}