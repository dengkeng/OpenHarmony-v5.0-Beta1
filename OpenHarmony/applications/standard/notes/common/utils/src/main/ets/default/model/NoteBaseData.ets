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

import NoteData from '../model/databaseModel/NoteData'

export const circleColorArray: string[] = [
  "#f86d05", // 深红
  "#ff7500", // 浅红
  "#ffbf00", // 黄色
  "#41ba41", // 绿色
  "#00bfc9", // 浅蓝
  "#00aaee", // 中蓝
  "#3f56ea", // 深蓝
  "#8a2be2", // 紫色
]

export const fontColorArray: string[] = [
  "#f86d05", // 深红
  "#ffbf00", // 黄色
  "#41ba41", // 绿色
  "#00aaee", // 中蓝
  "#3f56ea", // 深蓝
  "#8a2be2", // 紫色
  "#182431", //黑色
]

export const unSelectedNoteBgColorMap = {
  "#f86d05": "#fff8eceb",
  "#ff7500": "#f3d9c4",
  "#ffbf00": "#f3e8c4",
  "#41ba41": "#cde7d1",
  "#00bfc9": "#c0e8ec",
  "#00aaee": "#c0e4f4",
  "#3f56ea": "#cdd3f3",
  "#8a2be2": "#dccbf1",
  "#ffffff": "#ffffff"
}

export const selectedNoteBgColorMap = {
  "#f86d05": "#eec4b8",
  "#ff7500": "#f1d8c7",
  "#ffbf00": "#f3cdb1",
  "#41ba41": "#d1dabc",
  "#00bfc9": "#c5dbd4",
  "#00aaee": "#c5d7dc",
  "#3f56ea": "#d1c8db",
  "#8a2be2": "#dec1d9",
  "#ffffff": "#19007dff"
}

export const folderTextMap = {
  "sys_def_allNotes_uuid": $r('app.string.allNotes'),
  "sys_def_unClassified_uuid": $r('app.string.unClassified'),
  "sys_def_myFavorites_uuid": $r('app.string.myFavorites'),
  "sys_def_recentDeletes_uuid": $r('app.string.recentDeletes'),
}

export const folderIconMap = {
  "sys_def_allNotes_uuid": $r('app.media.allNotes'),
  "sys_def_unClassified_uuid": $r('app.media.unClassified'),
  "sys_def_myFavorites_uuid": $r('app.media.favorite_cancel'),
  "sys_def_recentDeletes_uuid": $r('app.media.delete'),
}

let CheckedNoteArray: NoteData[] = []

AppStorage.SetOrCreate('CheckedNoteArray', CheckedNoteArray)

export class WidthWeightMessage {
  folderListWeight: string // 三分栏每个分栏的比例， 用百分比表示 例如16%
  folderListVisibility: number // 分栏的可见性 0：表示Visibility.None 1：表示Visibility.Visible
  noteListWeight: string
  noteListVisibility: number
  noteCotentWeight: string
  noteCotentVisibility: number

  constructor(folderListWeight: string, folderListVisibility: number, noteListWeight: string, noteListVisibility: number,
              noteCotentWeight: string, noteCotentVisibility: number) {
    this.folderListWeight = folderListWeight
    this.folderListVisibility = folderListVisibility
    this.noteListWeight = noteListWeight
    this.noteListVisibility = noteListVisibility
    this.noteCotentWeight = noteCotentWeight
    this.noteCotentVisibility = noteCotentVisibility
  }
}

let widthWeightOneSection: WidthWeightMessage = new WidthWeightMessage("0%", 0, "0%", 0, "100%", 1)
let widthWeightTwoSection = new WidthWeightMessage("0%", 0, "34%", 1, "66%", 1)
let widthWeightThreeSection = new WidthWeightMessage("16%", 1, "34%", 1, "50%", 1)

export const widthWeightMessageMap = {
  1: widthWeightOneSection,
  2: widthWeightTwoSection,
  3: widthWeightThreeSection
}