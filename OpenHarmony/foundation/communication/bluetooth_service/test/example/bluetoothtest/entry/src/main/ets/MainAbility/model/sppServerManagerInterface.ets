/**
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

import bluetoothManager from '@ohos.bluetoothManager';
import promptAction from '@ohos.promptAction';

let serverNumber: number = - 1;

export function testSppServerCreateSafeManager(): string {
  try {
    let message = "sppServerCreateSafe test"
    console.log('spp server socketId(safe mode) create! ');
    let uuid: string = AppStorage.get('inputUuid') !
    if ( uuid == '' ) {
      message = 'uuid为空';
      promptAction.showToast({ message : message })
      return message
    }
    // 创建蓝牙服务器侦听套接字, 返回服务端ID
    bluetoothManager.sppListen('BluetoothDevice' , {
      uuid : uuid ,
      secure : true ,
      type : 0
    } , (code , serverSocketID) => {
      console.log('bluetooth error code: ' + typeof code + " ; " + JSON.stringify(code));
      if ( !code || code.code == 0 ) {
        console.log('spp server: serverSocketID(safe mode) - ' + serverSocketID);
        serverNumber = serverSocketID;
        message = "创建server成功";
        promptAction.showToast({ message : message })
      }
    });
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppServerCreateSafeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppServerCreateSafeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}


export function testSppServerCreateUnSafeManager(): string {
  try {
    let message = "sppServerCreateUnSafe test"
    let uuid: string = AppStorage.get('inputUuid') !
    console.log('spp server socketId(non-safe mode) create! ');
    if ( uuid == '' ) {
      message = 'uuid为空';
      promptAction.showToast({ message : message })
      return message
    }
    // 创建蓝牙服务器侦听套接字, 返回服务端ID
    bluetoothManager.sppListen('BluetoothDevice' , {
      uuid : uuid ,
      secure : false ,
      type : 0
    } , (code , serverSocketID) => {
      console.log('bluetooth error code: ' + typeof code + " ; " + JSON.stringify(code));
      if ( !code || code.code == 0 ) {
        console.log('spp server: serverSocketID(non-safe mode) ' + serverSocketID);
        serverNumber = serverSocketID;
        message = "创建server成功";
        promptAction.showToast({ message : message })
      }
    });
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppServerCreateUnSafeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppServerCreateUnSafeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

let clientNumber: number = - 1;

export function testSppServerAcceptManager(): string {
  try {
    let message = "testSppServerAccept test"
    let serverNumber: number = AppStorage.get("serverNumber") !
    console.log('testSppServerAccept test')
    console.log('testSppServerAccept serverNumber ' + serverNumber)
    bluetoothManager.sppAccept(serverNumber , (code , clientSocketID) => {
      console.log('bluetooth error code: ' + typeof code + " ; " + JSON.stringify(code));
      if ( !code || code.code == 0 ) {
        console.log('spp server: clientSocketID - ' + clientSocketID);
        console.log('test serverNumber ' + serverNumber);
        clientNumber = clientSocketID;
        //      AppStorage.setOrCreate("clientNumber",clientNumber)
        message = "接受客户端成功";
        bluetoothManager.on('sppRead' , clientNumber ,
          (dataBuffer: ArrayBuffer) => {
            const data = new Uint8Array(dataBuffer);
            console.log('spp bluetoothManager read is: ' + data);
            if ( data != null ) {
              message = "读取成功" + JSON.stringify(data);
            } else {
              message = "读取失败";
            }
            AppStorage.setOrCreate("dataReadMessage" , message)
          })
      }
      promptAction.showToast({ message : message })
      return message
    })
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppServerAcceptManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppServerAcceptManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppServerWriteManager(): string {
  try {
    let message = "sppServerWrite test"
    console.log(MODEL + 'sppWrite clientNumber: ' + JSON.stringify(clientNumber));
    let writeServerData: string = AppStorage.get("writeServerData") !
    let writeArrayBuffer: ArrayBuffer = strToArrayBuffer(writeServerData) as ArrayBuffer;
    bluetoothManager.sppWrite(clientNumber , writeArrayBuffer);
    console.log('sppWrite successfully');
    message = "写入成功 ";
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppServerWriteManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppServerWriteManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}


export function testSppServerReadOnManager(): string {
  try {
    let message = "sppServerReadOn test"
    bluetoothManager.on('sppRead' , clientNumber ,
      (dataBuffer: ArrayBuffer) => {
        const data = new Uint8Array(dataBuffer);
        console.log('spp bluetoothManager read is: ' + data);
        if ( data != null ) {
          message = "读取成功" + JSON.stringify(data);
        } else {
          message = "读取失败";
        }
        AppStorage.setOrCreate("dataReadMessage" , message)
        promptAction.showToast({ message : message })
        return message
      }
    );
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppServerReadOnManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppServerReadOnManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppServerReadOffManager(): string {
  try {
    let message = "sppServerReadOff test"
    bluetoothManager.off('sppRead' , clientNumber ,
      (dataBuffer: ArrayBuffer) => {
        const data = new Uint8Array(dataBuffer);
        console.log('spp bluetoothManager read is: ' + data);
        if ( data != null ) {
          message = "读取成功" + JSON.stringify(data);
        } else {
          message = "读取失败";
        }
        AppStorage.setOrCreate("dataReadMessage" , message)
        promptAction.showToast({ message : message })
        return message
      }
    );
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppServerReadOffManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppServerReadOffManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//关闭服务端serverSocket
let MODEL = "bluetoothModel:"

export function testSppCloseServerSocketManager(): String {
  try {
    let message = "sppServerClose test"
    console.log(MODEL + 'sppCloseServerSocket serverNumber: ' + serverNumber)
    bluetoothManager.sppCloseServerSocket(serverNumber);
    message = "关闭服务端";
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppCloseServerSocketManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppCloseServerSocketManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//关闭服务端accept回调的clientSocket
export function testSppCloseClientSocketManager(): String {
  try {
    let message = "sppCloseClientSocket test"
    console.log(MODEL + 'sppCloseClientSocket clientNumber: ' + clientNumber)
    bluetoothManager.sppCloseClientSocket(clientNumber);
    message = "关闭客户端";
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppCloseClientSocketManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppCloseClientSocketManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

function strToArrayBuffer(str: string) {
  let array = new Uint8Array(str.length);
  for ( let i = 0 ; i < str.length ; i ++ ) {
    array[ i ] = str.charCodeAt(i);
  }
  return array.buffer
}