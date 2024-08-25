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

import { BaseState } from './BaseState';
import { BaseIntent } from './BaseIntent';
import { BaseModel } from './BaseModel';
import Logger from '../utils/Logger';

const TAG = 'BaseViewModel';

/**
 *  results of enforcement
 */
export enum ProcessResult {
  FAIL = 0,
  SUCCESS = 1
}

export abstract class BaseViewModel<M extends BaseModel, S extends BaseState> {
  private _model?: M;
  private _viewState?: S;

  public getViewState(): S {
    if (this._viewState === null || this._viewState === undefined) {
      this._viewState = this.initViewState();
    }
    return this._viewState;
  }

  public async processIntent(intents: BaseIntent): Promise<ProcessResult> {
    Logger.info(TAG, 'start processIntent: ' + intents.getIntentTag());
    if (this._model === null || this._model === undefined) {
      this._model = this.initModel();
    }
    if (this._viewState === null || this._viewState === undefined) {
      this._viewState = this.initViewState();
    }
    if (this._model !== null && this._viewState !== null) {
      try {
        return await this.processIntentWithModel(intents, this._model, this._viewState);
      } catch (err) {
        Logger.error(TAG, 'error when process intents.' + intents.getIntentTag());
      }
    }
    return ProcessResult.FAIL;
  }

  protected abstract initModel(): M;

  protected abstract initViewState(): S;

  protected abstract processIntentWithModel(intents: BaseIntent, model: M, viewState: S): Promise<ProcessResult>;
}