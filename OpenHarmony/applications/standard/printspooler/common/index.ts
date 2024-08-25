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

export { SCHEME_IPP,
  SCHEME_IPPS,
  SERVICE_IPP,
  SERVICE_IPPS,
  EPSON_PRINTER,
  BISHENG_PRINTER,
  IPP_PORT,
  IPP_PATH,
  P2P_DISCOVERY_EVENT_ID,
  MDNS_EMITTER_EVENT_ID,
  WIFI_POWER_CLOSED,
  P2P_DISCOVERY_DELAY } from './src/main/ets/model/PrintConstants'

export {
  MessageEvent,
  PrinterFoundType,
  DateTimeFormat,
  CustomPrintJobState } from './src/main/ets/model/PrintBean'

export { MediaSize, Size, MediaSizeHelper } from './src/main/ets/model/MediaSize'

export { GlobalThisStorageKey } from './src/main/ets/model/GlobalThisStorageKey'

export { GlobalThisHelper} from './src/main/ets/model/GlobalThisHelper'

export { ErrorCode,
  ErrorMessage,
  CONNECTION_POP,
  INIT_ERROR,
  GET_CAPS_ERROR,
  IPP_CONNECT_ERROR,
  P2P_SERVICE_ERROR } from './src/main/ets/model/ErrorMessage'

export { uuidGenerator } from './src/main/ets/utils/UuidGenerator'

export { PrinterUtils } from './src/main/ets/utils/PrinterUtils'

export { checkWifiEnable } from './src/main/ets/utils/PermissionUtils'

export { MediaSizeUtil } from './src/main/ets/utils/MediaSizeUtil'

export { Log } from './src/main/ets/utils/Log'

export { DateUtils } from './src/main/ets/utils/DateUtils'

export { MediaTypes, MediaTypeCode } from './src/main/ets/model/MediaType'

export { default } from './src/main/ets/utils/CheckEmptyUtils';

export { CopyUtil } from './src/main/ets/utils/CopyUtil'

export { RequestCode,
  PrintErrorCode,
  WindowErrorCode,
  PrintRangeType,
  PageDirection,
  PrintQuality,
  Constants,
  AppStorageKeyName,
  AppCommonEvent,
  PreferencesKey,
  MouseState,
  MediaType,
  Duplex,
  ColorCode
} from './src/main/ets/model/Constants'

export { StringUtil } from './src/main/ets/utils/StringUtil'

export { PrintMargin,
  PrinterRange,
  PreviewAttribute,
  PrintResolution,
  PrintPageSize,
  PrinterCapability,
  PrinterInfo,
  PrinterCapsOptions,
  PrintJob,
  PrintJobOptions,
  PrinterExtensionInfo,
  startPrintJob,
  queryAllPrintJobs,
  cancelPrintJob,
  isValidPrintJob,
  convertToSpoolerPrintJob,
  convertToFwkPrintJob,
  convertToPrinterInfo } from './src/main/ets/framework/Print'

export { PrintJobChangeListener,
  PrintItemChangeListener,
  ConfigChangeListener } from './src/main/ets/framework/Interfaces'

export { PrintUtil } from './src/main/ets/utils/PrintUtil'

export  { GlobalObject } from './src/main/ets/utils/GlobalObject'

export { SingletonHelper } from './src/main/ets/utils/SingletonHelper'

export { configMgr } from './src/main/ets/framework/ConfigManager'