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
import { BasicApiInfo as nodeBaseApiInfo, ExportImportValue, ParentClass } from '../../typedef/parser/ApiInfoDefination';

import { StringConstant } from '../../utils/Constant';
import { Comment } from './Comment';

export class BasicApiInfo {
  apiType: string = ''; // api 类型
  constructor(apiType: string) {
    this.apiType = apiType;
  }
}

export class ApiInfo extends BasicApiInfo {
  name: string = ''; // api的名称
  syscap: string = ''; // api的系统能力
  since: string = '-1'; // api的起始版本
  isForm: boolean = false; // api是否支持卡片应用
  isCrossPlatForm: boolean = false; // api是否支持跨平台
  isSystemApi: boolean = false; // api是否是系统api
  isStageModelOnly: boolean = false; // api是否仅Stage模型可用
  isFaModelOnly: boolean = false; // api是否仅FA模型可用
  deprecatedVersion: string = '-1'; // api的废弃版本
  useinstead: string = ''; // api的替换接口

  constructor(apiType: string, jsDocInfo: Comment.JsDocInfo) {
    super(apiType);
    this.setJsDocInfo(jsDocInfo);
  }

  setJsDocInfo(jsDocInfo: Comment.JsDocInfo): ApiInfo {
    this.syscap = jsDocInfo.getSyscap();
    this.since = jsDocInfo.getSince();
    this.isForm = jsDocInfo.getIsForm();
    this.isCrossPlatForm = jsDocInfo.getIsCrossPlatForm();
    this.isSystemApi = jsDocInfo.getIsSystemApi();
    this.isStageModelOnly = jsDocInfo.getModelLimitation().toLowerCase() === StringConstant.STAGE_MODEL_ONLY;
    this.isFaModelOnly = jsDocInfo.getModelLimitation().toLowerCase() === StringConstant.FA_MODEL_ONLY;
    this.deprecatedVersion = jsDocInfo.getDeprecatedVersion();
    this.useinstead = jsDocInfo.getUseinstead();
    return this;
  }

  getSince(): string {
    return this.since;
  }

  setName(name: string | undefined): ApiInfo {
    if (!name) {
      return this;
    }
    this.name = name;
    return this;
  }
}

export class DeclareConstInfo extends ApiInfo {
  type: string = '';

  setType(type: string): DeclareConstInfo {
    this.type = type;
    return this;
  }
}

export class PropertyInfo extends ApiInfo {
  type: string = '';
  isReadOnly: boolean = false;
  isRequired: boolean = false;
  isStatic: boolean = false;
  permission: string = '';

  constructor(apiType: string, jsDocInfo: Comment.JsDocInfo) {
    super(apiType, jsDocInfo);
    this.setPermission(jsDocInfo.getPermission());
  }

  setType(type: string): PropertyInfo {
    this.type = type;
    return this;
  }

  setIsReadOnly(isReadOnly: boolean): PropertyInfo {
    this.isReadOnly = isReadOnly;
    return this;
  }

  setIsRequired(isRequired: boolean): PropertyInfo {
    this.isRequired = isRequired;
    return this;
  }

  setIsStatic(isStatic: boolean): PropertyInfo {
    this.isStatic = isStatic;
    return this;
  }

  setPermission(permission: string): PropertyInfo {
    this.permission = permission;
    return this;
  }
}

export class ConstantInfo extends ApiInfo {
  type: string = '';
  value: string = '';

  setType(type: string): ConstantInfo {
    this.type = type;
    return this;
  }

  setValue(value: string): ConstantInfo {
    this.value = value;
    return this;
  }
}

export class UnionTypeInfo extends ApiInfo {
  valueRange: string[] = [];

  addValueRange(value: string): UnionTypeInfo {
    this.valueRange.push(value);
    return this;
  }

  addValueRanges(valueRange: string[]): UnionTypeInfo {
    this.valueRange.push(...valueRange);
    return this;
  }
}

export class EnumValueInfo extends ApiInfo {
  value: string = '';

  setValue(value: string): EnumValueInfo {
    this.value = value;
    return this;
  }
}

export class TypeAliasInfo extends ApiInfo {
  type: string = '';

  setType(type: string): TypeAliasInfo {
    this.type = type;
    return this;
  }
}

export class MethodInfo extends ApiInfo {
  callForm: string = '';
  params: ParamInfo[] = [];
  returnValue: string = '';
  isStatic: boolean = false;
  permission: string = '';
  errorCodes: number[] = [];

  constructor(apiType: string, jsDocInfo: Comment.JsDocInfo) {
    super(apiType, jsDocInfo);
    this.setPermission(jsDocInfo.getPermission());
    this.setErrorCodes(jsDocInfo.getErrorCode());
  }

  setCallForm(callForm: string): MethodInfo {
    this.callForm = callForm;
    return this;
  }

  addParam(paramInfo: ParamInfo): MethodInfo {
    this.params.push(paramInfo);
    return this;
  }

  setReturnValue(returnValue: string): MethodInfo {
    this.returnValue = returnValue;
    return this;
  }

  setIsStatic(isStatic: boolean): MethodInfo {
    this.isStatic = isStatic;
    return this;
  }

  setPermission(permission: string): MethodInfo {
    this.permission = permission;
    return this;
  }

  setErrorCodes(errorCodes: number[]): MethodInfo {
    this.errorCodes.push(...errorCodes);
    return this;
  }
}

export class ParamInfo extends ApiInfo {
  type: string = '';
  isRequired: boolean = false;

  setType(type: string | undefined): void {
    if (!type) {
      return;
    }
    this.type = type;
  }

  setIsRequired(isRequired: boolean): void {
    this.isRequired = isRequired;
  }
}

export class NamespaceEnumInfo extends ApiInfo {
  childApis: BasicApiInfo[] = [];

  addChildApi(childApis: BasicApiInfo[]): NamespaceEnumInfo {
    this.childApis.push(...childApis);
    return this;
  }
}

export class ClassInterfaceInfo extends NamespaceEnumInfo {
  parentClasses: ParentClass[] = [];

  setParentClasses(parentClasses: ParentClass[]): ClassInterfaceInfo {
    this.parentClasses.push(...parentClasses);
    return this;
  }
}

export class ExportDefaultInfo extends BasicApiInfo {
  name: string = '';

  createObject(): ExportDefaultInfo {
    return new ExportDefaultInfo(this.apiType);
  }

  setName(name: string): ExportDefaultInfo {
    this.name = name;
    return this;
  }
}

export class ImportInfo extends BasicApiInfo {
  importValues: Array<ExportImportValue> = [];

  addImportValue(name: string, type: string): ImportInfo {
    this.importValues.push({ key: name, value: type || name });
    return this;
  }
}

export interface NodeProcessorInterface {
  (baseApiInfo: nodeBaseApiInfo): BasicApiInfo[];
}
