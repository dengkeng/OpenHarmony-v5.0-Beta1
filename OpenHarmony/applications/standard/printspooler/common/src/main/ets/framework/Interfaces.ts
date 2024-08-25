/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
 * controller层数据刷新回调model层
 */
export type PrintJobChangeListener = {
  onAddPrintJob: Function,
  onUpdatePrintJob: Function,
  onRemovePrintJob: Function,
  onAllPrintJobsFinished: Function
};
/**
 * 打印任务model层数据刷新后回调UI
 */
export type PrintItemChangeListener = {
  onPrintItemsChanged: Function
};
/**
 * 环境配置变化回调listener
 */
export type ConfigChangeListener = {
  notifyConfigurationChanged: Function
};