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
 * request code
 */
export enum RequestCode {
  START_DISCOVERY_CODE = 0,
  STOP_DISCOVERY_CODE,
  CONNECT_PRINTER_CODE,
  DISCONNECT_PRINTER_CODE,
  QUERY_PRINTER_CAPABILITY_CODE,
  CREATE_PRINT_JOB_CODE,
  START_PRINT_CODE,
  CANCEL_PRINT_CODE,
  QUERY_PRINT_EXTENSION_CODE,
  REQUEST_PREVIEW_CODE,
  OPEN_JOB_LIST_CODE,
}

export enum PrintErrorCode {
  E_PRINT_NONE = 0, // no error
  E_PRINT_NO_PERMISSION = 201, // no permission
  E_PRINT_INVALID_PARAMETER = 401, // invalid parameter
  E_PRINT_GENERIC_FAILURE = 13100001, // generic failure of print
  E_PRINT_RPC_FAILURE = 13100002, // RPC failure
  E_PRINT_SERVER_FAILURE = 13100003, // failure of print service
  E_PRINT_INVALID_EXTENSION = 13100004, // invalid print extension
  E_PRINT_INVALID_PRINTER = 13100005, // invalid printer
  E_PRINT_INVALID_PRINTJOB = 13100006, // invalid print job
  E_PRINT_FILE_IO = 13100007, // file i/o error
}


export enum WindowErrorCode {
  REPEATED_OPERATION = 1300001, // Repeated operation.
  WINDOW_STATE_ABNORMAL = 1300002, // This window state is abnormal.
  UNAUTHORIZED_OPERATION = 1300004 // Unauthorized operation.
}

export enum PrintRangeType {
  ALL = 0, //全部页面
  RANGE = 1, //范围
  CUSTOM = 2 //自定义
}

export enum PageDirection {
  AUTO = 0, //自适应
  VERTICAL = 1, //竖向
  LANDSCAPE = 2 //横向
}

export enum PrintQuality {
  ECONOMY = 3, //经济
  STANDARD = 4, //标准
  BEST = 5 //最佳
}

export enum Duplex {
  SINGLE = 0, //单面
  LONG = 1, //双面沿长边
  SHORT = 2 //双面沿短边
}

export enum ColorCode {
  MONOCHROME = 0, //黑白
  COLOR = 1 //彩色
}

export enum MediaType {
  NORMAL = 0, //普通纸
  PHOTO = 10 //相片纸
}

export enum MouseState {
  NONE = 0,
  PRESS = 1,
  HOVER = 2,
}

export class Constants {
  static readonly NEGATIVE_1: number = -1;
  static readonly NUMBER_0: number = 0;
  static readonly NUMBER_1: number = 1;
  static readonly NUMBER_2: number = 2;
  static readonly NUMBER_3: number = 3;
  static readonly NUMBER_4: number = 4;
  static readonly NUMBER_5: number = 5;
  static readonly NUMBER_6: number = 6;
  static readonly NUMBER_7: number = 7;
  static readonly NUMBER_8: number = 8;
  static readonly NUMBER_9: number = 9;
  static readonly NUMBER_10: number = 10;
  static readonly NUMBER_11: number = 11;
  static readonly NUMBER_48: number = 48;
  static readonly NUMBER_90: number = 90;
  static readonly NUMBER_99: number = 99;

  static readonly CONNECT_COUNT: number = 40;
  static readonly COUNTDOWN_INTERVAL: number = 1000;
  static readonly TOAST_INTERVAL: number = 2000;
  static readonly TOAST_BOTTOM: number = 64;
  static readonly SHOW_TOAST_TIMEOUT: number = 200;
  static readonly COUNTDOWN_ALARM_TO_FAIL: number = 26;
  static readonly COUNTDOWN_TO_FAIL: number = 25;
  static readonly CANVAS_MAX_WIDTH: number = 432;
  static readonly CANVAS_MAX_HEIGHT: number = 302;
  static readonly MAX_PIXELMAP: number = 33554432;
  static readonly MAX_PAGES: number = 100;
  static readonly MAX_CUSTOM_PRINT_RANGE_LENGTH: number = 50;

  static readonly MAIN_WINDOW_WIDTH: number = 480;
  static readonly MAIN_WINDOW_HEIGHT: number = 853;
  static readonly JOB_WINDOW_WIDTH: number = 394;
  static readonly JOB_WINDOW_HEIGHT: number = 550;

  static readonly READ: number = 0o0;
  static readonly READ_WRITE: number = 0o2;
  static readonly CREATE: number = 0o100;
  static readonly OPEN_SYNC1: number = 0o102;
  static readonly OPEN_SYNC2: number = 0o640;
  static readonly OPEN_FAIL: number = -1;

  static readonly STRING_NONE: string = '';
  static readonly STRING_ONE: string = '1';
  static readonly STRING_NEGATIVE_ONE: string = '-1';
  static readonly STRING_99: string = '99';

  static readonly BUNDLE_NAME: string = 'com.ohos.spooler';
  static readonly MAIN_ABILITY_NAME: string = 'MainAbility';
  static readonly JOB_MANAGER_ABILITY_NAME: string = 'JobManagerAbility';
  static readonly KEEP_ALIVE_ABILITY_NAME: string = 'KeepAliveAbility';
  static readonly MAIN_SERVICE_DESCRIPTOR: string = 'PrintSpoolerService';
  static readonly KEEP_ALIVE_SERVICE_DESCRIPTOR: string = 'KeepAliveService';
  static readonly WANT_JOB_ID_KEY: string = 'jobId';
  static readonly WANT_FILE_LIST_KEY: string = 'fileList';
  static readonly WANT_CALLERPID_KEY: string = 'ohos.aafwk.param.callerUid';
  static readonly WANT_PKG_NAME_KEY: string = 'caller.pkgName';
  static readonly EVENT_GET_ABILITY_DATA: string = 'getAbilityData';
  static readonly DEFAULT_CONNECTING_PRINTER_ID: string = 'noNeedDisconnect';
  static readonly WINDOW_FLOAT_MODE: number = 102;
  static readonly PRINT_JOB_NOTIFICATION_ID: number = 2000;
  static readonly SHOW_JOB_COMPLETED_TIMEOUT: number = 3000; // 3秒
  static readonly FILE_SEPARATOR = '/';
  static readonly CN_COMMA = '，';
  static readonly EU_COMMA = ',';
  static readonly HYPHEN = '-';
  static readonly DOT = '.';
  static readonly MDNS_PRINTER = 'mdns:';
  static readonly TEMP_JOB_FOLDER = 'jobs';
  static readonly JPEG_SUFFIX = '.jpeg';
}

export class AppStorageKeyName {
  static readonly JOB_QUEUE_NAME: string = 'JobQueue';
  static readonly PRINTER_QUEUE_NAME: string = 'PrinterQueue';
  static readonly PRINT_EXTENSION_LIST_NAME: string = 'PrintExtensionsList';
  static readonly CONFIG_LANGUAGE: string = 'configLanguage';
  static readonly START_PRINT_TIME: string = 'startPrintTime';
  static readonly INGRESS_PACKAGE: string = 'ingressPackage';
  static readonly APP_VERSION: string = 'appVersion';
}

export class GlobalThisStorageKey {
  static readonly KEY_SERVICE_CONNECT_OPTIONS: string = 'ServiceConnectOptions';
  static readonly KEY_JOB_ID: string = 'JobId';
  static readonly KEY_MEDIA_SIZE_UTIL: string = 'mediaSizeUtil';
  static readonly KEY_PRINT_ADAPTER: string = 'printAdapter';
  static readonly KEY_PREFERENCES_ADAPTER: string = 'preferencesAdapter';
  static readonly KEY_MAIN_ABILITY_CONTEXT: string = 'mainAbilityContext';
  static readonly KEY_MAIN_ABILITY_WINDOW_STAGE: string = 'mainAbilityWindowStage';
  static readonly KEY_JOB_MANAGER_ABILITY_CONTEXT: string = 'jobManagerAbilityContext';
  static readonly KEY_NOTIFICATION_PRINTER_NAME: string = 'notificationPrinterName';
  static readonly KEY_SERVICE_FIRST_START: string = 'serviceFirstStart';
  static readonly KEY_PRINTER_SELECT_DIALOG_OPEN: string = 'printerSelectDialogOpen';
  static readonly KEY_CURRENT_PIXELMAP: string = 'currentPixelMap';
  static readonly KEY_XGATE_USERNAME: string = 'xGateUserName';
  static readonly KEY_SECURITY_GUARD: string = 'securityGuard';
  static readonly KEY_IMAGE_ERROR_COUNT: string = 'imageErrorCount';
  static readonly KEY_IMAGE_ERROR_NAME: string = 'imageErrorName';
}

// 应用内公共事件
export class AppCommonEvent {
  static readonly PRINTER_STATE_CHANGE_EVENT: number = 1000;
  static readonly PRINTER_UPDATE_CAPABILITY_EVENT: number = 1001;
  static readonly START_JOB_MANAGER_ABILITY_EVENT: number = 1002;
  static readonly TERMINATE_JOB_MANAGER_ABILITY_EVENT: number = 1003;
  static readonly PRINTER_INVALID_EVENT: number = 1004;
  static readonly WLAN_INACTIVE_EVENT: number = 1005;
  static readonly WLAN_ACTIVE_EVENT: number = 1006;
  static readonly ADD_PRINTER_EVENT: number = 1007;
}

export class PreferencesKey {
  static readonly KEY_PRIVACY_STATEMENT_PREFERENCES: string = 'AGREE_PRIVACY_STATEMENT';
}


