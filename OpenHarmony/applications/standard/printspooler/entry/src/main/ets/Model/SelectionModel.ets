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

import CheckEmptyUtils, { PageDirection, PrintQuality, MediaType ,Duplex, MediaSizeHelper} from '@ohos/common'
import { Log, MediaSize } from '@ohos/common'

const TAG = '[SelectionModel]:'
export default class SelectionModel {
  public static selectionMap: Map<string, object> = new Map();
  public static readonly Add_Printer: SelectionModel = new SelectionModel('index_add_printer'
    , $r('app.string.index_add_printer'))
  public static readonly NO_Printer: SelectionModel = new SelectionModel('index_no_printer_selected'
    , $r('app.string.index_no_printer_selected'))
  public static readonly MediaSize_ISO_A3: SelectionModel = new SelectionModel('ISO_A3'
    , MediaSizeHelper.ISO_A3.label)
  public static readonly MediaSize_ISO_A4: SelectionModel = new SelectionModel('ISO_A4'
    , MediaSizeHelper.ISO_A4.label)
  public static readonly MediaSize_ISO_A5: SelectionModel = new SelectionModel('ISO_A5'
    , MediaSizeHelper.ISO_A5.label)
  public static readonly MediaSize_JIS_B5: SelectionModel = new SelectionModel('JIS_B5'
    , MediaSizeHelper.JIS_B5.label)
  public static readonly MediaSize_ISO_C5: SelectionModel = new SelectionModel('ISO_C5'
    , '')
  public static readonly MediaSize_ISO_DL: SelectionModel = new SelectionModel('ISO_DL'
    , '')
  public static readonly MediaSize_LETTER: SelectionModel = new SelectionModel('LETTER'
    , MediaSizeHelper.LETTER.label)
  public static readonly MediaSize_LEGAL: SelectionModel = new SelectionModel('LEGAL'
    , MediaSizeHelper.LEGAL.label)
  public static readonly MediaSize_PHOTO_4x6: SelectionModel = new SelectionModel('PHOTO_4x6'
    , '')
  public static readonly MediaSize_PHOTO_5x7: SelectionModel = new SelectionModel('PHOTO_5x7'
    , '')
  public static readonly MediaSize_INT_DL_ENVELOPE: SelectionModel = new SelectionModel('INT_DL_ENVELOPE'
    , MediaSizeHelper.INT_DL_ENVELOPE.label)
  public static readonly MediaSize_B_TABLOID: SelectionModel = new SelectionModel('B_TABLOID'
    , MediaSizeHelper.B_TABLOID.label)
  public static readonly Direction_AUTO: SelectionModel = new SelectionModel('PageDirection_AUTO'
    , $r('app.string.PageDirection_AUTO'))
  public static readonly Direction_LANDSCAPE: SelectionModel = new SelectionModel('PageDirection_LANDSCAPE'
    , $r('app.string.PageDirection_LANDSCAPE'))
  public static readonly Direction_VERTICAL: SelectionModel = new SelectionModel('PageDirection_VERTICAL'
    , $r('app.string.PageDirection_VERTICAL'))
  public static readonly MediaType_NORMAL: SelectionModel = new SelectionModel('MediaType_NORMAL'
    , $r('app.string.MediaType_NORMAL'))
  public static readonly MediaType_PHOTO: SelectionModel = new SelectionModel('MediaType_PHOTO'
    , $r('app.string.MediaType_PHOTO'))
  public static readonly PrintQuality_BEST: SelectionModel = new SelectionModel('PrintQuality_BEST'
    , $r('app.string.PrintQuality_BEST'))
  public static readonly PrintQuality_STANDARD: SelectionModel = new SelectionModel('PrintQuality_STANDARD'
    , $r('app.string.PrintQuality_STANDARD'))
  public static readonly PrintQuality_ECONOMY: SelectionModel = new SelectionModel('PrintQuality_ECONOMY'
    , $r('app.string.PrintQuality_ECONOMY'))
  public static readonly DuplexMode_SINGLE: SelectionModel = new SelectionModel('DuplexMode_ONESIDE'
    , $r('app.string.DuplexMode_ONESIDE'))
  public static readonly DuplexMode_LONG: SelectionModel = new SelectionModel('DuplexMode_LONG'
    , $r('app.string.DuplexMode_LONG'))
  public static readonly DuplexMode_SHORT: SelectionModel = new SelectionModel('DuplexMode_SHORT'
    , $r('app.string.DuplexMode_SHORT'))
  public static MediaSizeSelections: SelectionModel[] = [];
  public name: string; // 选项名称
  public res: Resource | string;

  constructor(name: string, res: Resource | string) {
    this.name = name;
    this.res = res;
  }

  public static initSelectionMap():void{
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.ISO_A3,'ISO_A3');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.ISO_A4,'ISO_A4');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.ISO_A5,'ISO_A5');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.JIS_B5,'JIS_B5');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.ISO_C5,'ISO_C5');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.ISO_DL,'ISO_DL');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.LETTER,'LETTER');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.LEGAL,'LEGAL');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.PHOTO_4x6,'PHOTO_4x6');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.PHOTO_5x7,'PHOTO_5x7');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.INT_DL_ENVELOPE,'INT_DL_ENVELOPE');
    SelectionModel.createSelectionValue<MediaSize>(MediaSizeHelper.B_TABLOID,'B_TABLOID');

    SelectionModel.createSelectionValue<number>(PageDirection.AUTO,'PageDirection_AUTO');
    SelectionModel.createSelectionValue<number>(PageDirection.LANDSCAPE,'PageDirection_LANDSCAPE');
    SelectionModel.createSelectionValue<number>(PageDirection.VERTICAL,'PageDirection_VERTICAL');
    SelectionModel.createSelectionValue<number>(MediaType.NORMAL,'MediaType_NORMAL');
    SelectionModel.createSelectionValue<number>(MediaType.PHOTO,'MediaType_PHOTO');
    SelectionModel.createSelectionValue<number>(PrintQuality.BEST,'PrintQuality_BEST');
    SelectionModel.createSelectionValue<number>(PrintQuality.STANDARD,'PrintQuality_STANDARD');
    SelectionModel.createSelectionValue<number>(PrintQuality.ECONOMY,'PrintQuality_ECONOMY');
    SelectionModel.createSelectionValue<number>(Duplex.SINGLE,'DuplexMode_ONESIDE');
    SelectionModel.createSelectionValue<number>(Duplex.LONG,'DuplexMode_LONG');
    SelectionModel.createSelectionValue<number>(Duplex.SHORT,'DuplexMode_SHORT');
  }

  public static createSelectionValue<T>(value: T, name: string): void {
    SelectionModel.selectionMap[name] = value;
    Log.debug(TAG, 'createSelectionValue name = ' + name);
  }

  public static getSelectionValue<T>(name: string): T | undefined {
    if (SelectionModel.selectionMap[name] === undefined) {
      Log.error(TAG, 'getSelectionValue name not exist: ' + name);
      return undefined;
    }
    return (SelectionModel.selectionMap[name] as T);
  }

  public static getSelectionModelByLabel(label: string): SelectionModel | undefined {
    if (CheckEmptyUtils.isEmptyArr(SelectionModel.MediaSizeSelections)) {
      SelectionModel.initMediaSizeSelections();
    }
    let rtnSelect: SelectionModel | undefined = undefined;
    SelectionModel.MediaSizeSelections.forEach((selection, index, all) => {
      if (selection.res === label) {
        rtnSelect = selection;
      }
    })
    return rtnSelect;
  }

  public static initMediaSizeSelections(){
    SelectionModel.MediaSizeSelections = [];
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_ISO_A3);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_ISO_A4);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_ISO_A5);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_ISO_C5);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_ISO_DL);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_JIS_B5);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_LEGAL);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_LETTER);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_PHOTO_4x6);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_PHOTO_5x7);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_INT_DL_ENVELOPE);
    SelectionModel.MediaSizeSelections.push(SelectionModel.MediaSize_B_TABLOID);
  }
}
