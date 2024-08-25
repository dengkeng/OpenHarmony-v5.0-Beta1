/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import ts from 'typescript';
import { EventConstant } from '../../../utils/Constant';
import { EventMethodData, CollectParamStatus } from '../../../typedef/checker/event_method_check_interface';
import { ErrorID, ErrorLevel, ErrorMessage, ErrorType, LogType } from '../../../typedef/checker/result_type';
import { ApiInfo, ApiType, BasicApiInfo, MethodInfo, ParamInfo } from '../../../typedef/parser/ApiInfoDefination';
import { CommonFunctions } from '../../../utils/checkUtils';
import { FilesMap, Parser } from '../../parser/parser';
import { AddErrorLogs } from './compile_info';
import { compositiveResult, compositiveLocalResult } from '../../../utils/checkUtils';
import { CheckHump } from './check_hump';

export class EventMethodChecker {
  private apiData: FilesMap;
  constructor(apiData: FilesMap) {
    this.apiData = apiData;
  }

  public getAllEventMethod(): Map<string, EventMethodData> {
    const allBasicApi: BasicApiInfo[] = Parser.getAllBasicApi(this.apiData);
    const eventMethodInfo: BasicApiInfo[] = [];
    allBasicApi.forEach((basicApi: BasicApiInfo) => {
      const lastSince: string | undefined = basicApi.jsDocText.length > 0 ? (basicApi as ApiInfo).getLastJsDocInfo()?.since : '-1';
      if (basicApi.apiType === ApiType.METHOD && this.isEventMethod(basicApi.apiName) &&
        lastSince === CommonFunctions.getCheckApiVersion()) {
        eventMethodInfo.push(basicApi);
      }
    });
    const eventMethodDataMap: Map<string, EventMethodData> = this.getEventMethodDataMap(eventMethodInfo);
    return eventMethodDataMap;
  }

  public checkEventMethod(eventMethodData: Map<string, EventMethodData>): void {
    eventMethodData.forEach((eventMethod: EventMethodData) => {
      // check on&off event pair
      if ((eventMethod.onEvents.length === 0 && eventMethod.offEvents.length !== 0) ||
        (eventMethod.onEvents.length !== 0 && eventMethod.offEvents.length === 0)) {
        const firstEvent: BasicApiInfo = eventMethod.onEvents.concat(eventMethod.offEvents)[0];
        const errorMessage: string = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_EVENT_ON_AND_OFF_PAIR, []);
        AddErrorLogs.addAPICheckErrorLogs(
          ErrorID.API_PAIR_ERRORS_ID,
          ErrorLevel.MIDDLE,
          firstEvent.getFilePath(),
          firstEvent.getPos(),
          ErrorType.API_PAIR_ERRORS,
          LogType.LOG_API,
          parseInt(firstEvent.getCurrentVersion()),
          firstEvent.getApiName(),
          firstEvent.getDefinedText(),
          errorMessage,
          compositiveResult,
          compositiveLocalResult
        );
      }

      // check off event
      let offEvnetCallbackNumber: number = 0;
      let offCallbackRequiredNumber: number = 0;
      for (let i = 0; i < eventMethod.offEvents.length; i++) {
        const offEvent: MethodInfo = eventMethod.offEvents[i] as MethodInfo;
        if (offEvent.getParams().length < 2) {
          continue;
        }
        const eventCallbackStatus: CollectParamStatus = this.collectEventCallback(offEvent, offEvnetCallbackNumber,
          offCallbackRequiredNumber);
        offEvnetCallbackNumber = eventCallbackStatus.callbackNumber;
        offCallbackRequiredNumber = eventCallbackStatus.requiredCallbackNumber;
      }
      if (eventMethod.offEvents.length > 0) {
        if ((offEvnetCallbackNumber !== 0 && offEvnetCallbackNumber === eventMethod.offEvents.length &&
          offEvnetCallbackNumber === offCallbackRequiredNumber) ||
          (offEvnetCallbackNumber === 0 && eventMethod.offEvents.length !== 0)) {
          const firstEvent: BasicApiInfo = eventMethod.offEvents[0];
          const errorMessage: string = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_EVENT_CALLBACK_OPTIONAL, []);
          AddErrorLogs.addAPICheckErrorLogs(
            ErrorID.PARAMETER_ERRORS_ID,
            ErrorLevel.MIDDLE,
            firstEvent.getFilePath(),
            firstEvent.getPos(),
            ErrorType.PARAMETER_ERRORS,
            LogType.LOG_API,
            parseInt(firstEvent.getCurrentVersion()),
            firstEvent.getApiName(),
            firstEvent.getDefinedText(),
            errorMessage,
            compositiveResult,
            compositiveLocalResult
          );
        }
      }

      // check event first param
      const allEvnets: BasicApiInfo[] = eventMethod.onEvents.concat(eventMethod.offEvents)
        .concat(eventMethod.emitEvents).concat(eventMethod.onceEvents);
      for (let i = 0; i < allEvnets.length; i++) {
        const event: BasicApiInfo = allEvnets[i];
        if (!this.checkVersionNeedCheck(event)) {
          continue;
        }
        const eventParams: ParamInfo[] = (event as MethodInfo).getParams();
        if (eventParams.length < 1) {
          const errorMessage: string = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_EVENT_WITHOUT_PARAMETER, []);
          AddErrorLogs.addAPICheckErrorLogs(
            ErrorID.PARAMETER_ERRORS_ID,
            ErrorLevel.MIDDLE,
            event.getFilePath(),
            event.getPos(),
            ErrorType.PARAMETER_ERRORS,
            LogType.LOG_API,
            parseInt(event.getCurrentVersion()),
            event.getApiName(),
            event.getDefinedText(),
            errorMessage,
            compositiveResult,
            compositiveLocalResult
          );
          continue;
        }
        const firstParam: ParamInfo = eventParams[0];
        if (firstParam.getParamType() === ts.SyntaxKind.LiteralType) {
          const paramTypeName: string = firstParam.getType()[0].replace(/\'/g, '');
          if (paramTypeName === '') {
            const errorMessage: string = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_EVENT_NAME_NULL,
              [firstParam.getApiName()]);
            AddErrorLogs.addAPICheckErrorLogs(
              ErrorID.PARAMETER_ERRORS_ID,
              ErrorLevel.MIDDLE,
              event.getFilePath(),
              event.getPos(),
              ErrorType.PARAMETER_ERRORS,
              LogType.LOG_API,
              parseInt(event.getCurrentVersion()),
              event.getApiName(),
              event.getDefinedText(),
              errorMessage,
              compositiveResult,
              compositiveLocalResult
            );
          } else if (!CheckHump.checkSmallHump(paramTypeName)) {
            const errorMessage: string = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_EVENT_NAME_SMALL_HUMP,
              [paramTypeName]);
            AddErrorLogs.addAPICheckErrorLogs(
              ErrorID.PARAMETER_ERRORS_ID,
              ErrorLevel.MIDDLE,
              event.getFilePath(),
              event.getPos(),
              ErrorType.PARAMETER_ERRORS,
              LogType.LOG_API,
              parseInt(event.getCurrentVersion()),
              event.getApiName(),
              event.getDefinedText(),
              errorMessage,
              compositiveResult,
              compositiveLocalResult
            );
          }
        } else if (firstParam.getParamType() !== ts.SyntaxKind.StringKeyword) {
          const errorMessage: string = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_EVENT_NAME_STRING,
            [firstParam.getApiName()]);
          AddErrorLogs.addAPICheckErrorLogs(
            ErrorID.PARAMETER_ERRORS_ID,
            ErrorLevel.MIDDLE,
            event.getFilePath(),
            event.getPos(),
            ErrorType.PARAMETER_ERRORS,
            LogType.LOG_API,
            parseInt(event.getCurrentVersion()),
            event.getApiName(),
            event.getDefinedText(),
            errorMessage,
            compositiveResult,
            compositiveLocalResult
          );
        }
      }
    });
  }

  private checkVersionNeedCheck(eventInfo: BasicApiInfo): boolean {
    return parseInt(eventInfo.getCurrentVersion()) >= EventConstant.eventMethodCheckVersion;
  }

  private collectEventCallback(offEvent: MethodInfo,
    callbackNumber: number, requiredCallbackNumber: number): CollectParamStatus {
    const lastParam: ParamInfo = offEvent.getParams().slice(-1)[0];
    if (lastParam.paramType) {
      const basicTypes = new Set([ts.SyntaxKind.NumberKeyword, ts.SyntaxKind.StringKeyword,
      ts.SyntaxKind.BooleanKeyword, ts.SyntaxKind.UndefinedKeyword, ts.SyntaxKind.LiteralType]);
      if (!basicTypes.has(lastParam.paramType)) {
        callbackNumber++;
        if (lastParam.getIsRequired()) {
          requiredCallbackNumber++;
        }
      }
    }
    return {
      callbackNumber: callbackNumber,
      requiredCallbackNumber: requiredCallbackNumber
    };
  }

  private getEventMethodDataMap(eventInfos: BasicApiInfo[]): Map<string, EventMethodData> {
    let eventMethodDataMap: Map<string, EventMethodData> = new Map();
    eventInfos.forEach((eventInfo: BasicApiInfo) => {
      const directorRelations: string[] = [...eventInfo.hierarchicalRelations];
      directorRelations.pop();
      const apiCompletePath: string = [...directorRelations, this.getEventName(eventInfo.apiName)].join('/');
      let eventMethodData: EventMethodData = {
        onEvents: [],
        offEvents: [],
        emitEvents: [],
        onceEvents: []
      };
      if (eventMethodDataMap.get(apiCompletePath)) {
        eventMethodData = eventMethodDataMap.get(apiCompletePath) as EventMethodData;
      }
      eventMethodDataMap.set(apiCompletePath, this.collectEventMethod(eventMethodData, eventInfo));
    });
    return eventMethodDataMap;
  }

  private collectEventMethod(eventMethodData: EventMethodData, eventInfo: BasicApiInfo): EventMethodData {
    const eventType: string = this.getEventType(eventInfo.apiName);
    switch (eventType) {
      case 'on':
        eventMethodData.onEvents.push(eventInfo);
        break;
      case 'off':
        eventMethodData.offEvents.push(eventInfo);
        break;
      case 'emit':
        eventMethodData.emitEvents.push(eventInfo);
        break;
      case 'once':
        eventMethodData.onceEvents.push(eventInfo);
        break;
    }
    return eventMethodData;
  }

  private getEventName(apiName: string): string {
    return apiName.split(/\_/)[1];
  }

  private getEventType(apiName: string): string {
    return apiName.split(/\_/)[0];
  }

  private isEventMethod(apiName: string): boolean {
    const eventNameReg: RegExp = new RegExp(`^(${EventConstant.eventNameList.join('|')})\_`);
    return eventNameReg.test(apiName);
  }
}
