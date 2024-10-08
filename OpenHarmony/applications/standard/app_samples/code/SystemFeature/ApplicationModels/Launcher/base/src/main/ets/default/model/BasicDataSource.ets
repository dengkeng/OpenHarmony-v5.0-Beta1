/*
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

import MissionInfo from '../bean/MisssionInfo';
import { GridLayoutItemInfo } from '../bean/GridLayoutItemInfo';

class BasicDataSource implements IDataSource {
  private listeners: DataChangeListener[] = [];

  public totalCount(): number {
    return 0;
  }
  public getData(index: number): Object | undefined {
    return undefined;
  }

  registerDataChangeListener(listener: DataChangeListener): void {
    if (this.listeners.indexOf(listener) < 0) {
      console.info('add listener');
      this.listeners.push(listener);
    }
  }
  unregisterDataChangeListener(listener: DataChangeListener): void {
    const pos = this.listeners.indexOf(listener);
    if (pos >= 0) {
      console.info('remove listener');
      this.listeners.splice(pos, 1);
    }
  }

  notifyDataReload(): void {
    this.listeners.forEach(listener => {
      listener.onDataReloaded();
    })
  }
  notifyDataAdd(index: number): void {
    this.listeners.forEach(listener => {
      listener.onDataAdd(index);
    })
  }
  notifyDataChange(index: number): void {
    this.listeners.forEach(listener => {
      listener.onDataChange(index);
    })
  }
  notifyDataDelete(index: number): void {
    this.listeners.forEach(listener => {
      listener.onDataDelete(index);
    })
  }
  notifyDataMove(from: number, to: number): void {
    this.listeners.forEach(listener => {
      listener.onDataMove(from, to);
    })
  }
}

export class MyDataSource extends BasicDataSource {
  dataArray: MissionInfo[] = [];

  constructor(data: MissionInfo[]) {
    super();
    this.dataArray = data;
  }

  public totalCount(): number {
    return this.dataArray.length;
  }
  public getData(index: number): MissionInfo {
    return this.dataArray[index];
  }

  public addData(index: number, data: MissionInfo): void {
    this.dataArray.splice(index, 0, data);
    this.notifyDataAdd(index);
  }
  public pushData(data: MissionInfo): void {
    this.dataArray.push(data);
    this.notifyDataAdd(this.dataArray.length - 1);
  }
}

export class LauncherDataSource extends BasicDataSource {
  dataArray: GridLayoutItemInfo[] = [];

  constructor(data: GridLayoutItemInfo[]) {
    super();
    this.dataArray = data;
  }

  public totalCount(): number {
    return this.dataArray.length;
  }
  public getData(index: number): GridLayoutItemInfo {
    return this.dataArray[index];
  }

  public addData(index: number, data: GridLayoutItemInfo): void {
    this.dataArray.splice(index, 0, data);
    this.notifyDataAdd(index);
  }
  public pushData(data: GridLayoutItemInfo): void {
    this.dataArray.push(data);
    this.notifyDataAdd(this.dataArray.length - 1);
  }
}