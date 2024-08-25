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

import CallServiceProxy from '../../model/CallServiceProxy';
import DtmfBtn from '../components/DtmfBtn';
import DefaultCallData from '../struct/TypeUtils';

class DataListStruct {
  public value: string
  public sign: string
}
const TAG = 'Keyboard';

@Component
export default struct Keyboard {
  @Link callData: DefaultCallData;
  @StorageLink('TextInput') textInput: string = '';
  @StorageLink('TextInputValue') textInputValue: string = '';
  @State dataList: Array<DataListStruct> =
    [
      {
        value: '1',
        sign: 'o_o'
      },
      {
        value: '2',
        sign: 'ABC'
      },
      {
        value: '3',
        sign: 'DEF'
      },
      {
        value: '4',
        sign: 'GHI'
      },
      {
        value: '5',
        sign: 'JKL'
      },
      {
        value: '6',
        sign: 'MNO'
      },
      {
        value: '7',
        sign: 'PQRS'
      },
      {
        value: '8',
        sign: 'TUV'
      },
      {
        value: '9',
        sign: 'WXYZ'
      },
      {
        value: '*',
        sign: '(P)'
      },
      {
        value: '0',
        sign: '+'
      },
      {
        value: '#',
        sign: '(W)'
      },
    ];
  private mCallServiceProxy: CallServiceProxy;

  public aboutToAppear(): void {
    this.mCallServiceProxy = CallServiceProxy.getInstance();
  }

  build() {
    GridRow({ columns: { sm: 4, md: 8, lg: 12 }, gutter: 24 }) {
      GridCol({ span: { sm: 4, md: 6, lg: 6 }, offset: { md: 1, lg: 3 } }) {
        Grid() {
          ForEach(this.dataList, (item) => {
            GridItem() {
              DtmfBtn({
                item: item,
                textInput: $textInput,
                textInputValue: $textInputValue,
                dataList: $dataList,
                callData: this.callData
              })
            }
            .height(56.5)
          })
        }
        .columnsGap(24)
        .rowsGap(20.5)
        .columnsTemplate('1fr 1fr 1fr')
        .rowsTemplate('1fr 1fr 1fr 1fr')
      }
      .height(287.5)
    }
    .margin({ left: 24, right: 24 })
  }
}