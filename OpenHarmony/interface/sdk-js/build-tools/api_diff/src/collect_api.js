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

const path = require('path');
const fs = require('fs');
const ts = require('typescript');
const ExcelJS = require('exceljs');
const compressing = require('compressing');
const { readFile, getSubsystemBySyscap, getApiInfoWithFlag, getApiInfoDeleteDtsPath } = require('./util');
const { parse } = require('./collect_base_api');
const { allMergeData } = require('./format_data');
let methodType = '';

function getSubsystemJson(jsonDir) {
  let fileContent = fs.readFileSync(jsonDir, 'utf-8');
  let subsystems = JSON.parse(fileContent);
  const subsystemMap = new Map();
  const fileNameMap = new Map();
  subsystems.forEach(element => {
    subsystemMap.set(element.syscap, element.subsystem);
    fileNameMap.set(element.syscap, element.fileName);
  });
  return { subsystemMap, fileNameMap };
}

// 对比新旧版本文件列表
function compileFiles(newFiles, oldFiles) {
  const newFileNames = [];
  const oldFileNames = [];
  newFiles.forEach(file => {
    const fileName = path.basename(file).replace(/.d.ts$/g, '.ts');
    newFileNames.push(fileName);
  });
  oldFiles.forEach(file => {
    const fileName = path.basename(file).replace(/.d.ts$/g, '.ts');
    oldFileNames.push(fileName);
  });

  //保存有差异的信息
  const compileApiInfos = [];
  // 旧版本不存在新版本中的文件，表示新增
  newFileNames.forEach(fileName => {
    let index = oldFileNames.indexOf(fileName);
    if (index < 0) {
      compileApiInfos.push({
        flag: '新版本新增',
        fileName: fileName,
        filePath: newFiles[newFileNames.indexOf(fileName)],
      });
    }
  });
  // 新版本不在在旧版本中的文件，表示删除
  oldFileNames.forEach(fileName => {
    let index = newFileNames.indexOf(fileName);
    if (index < 0) {
      compileApiInfos.push({
        flag: '新版本删除',
        fileName: fileName,
        filePath: oldFiles[oldFileNames.indexOf(fileName)],
      });
    }
  });

  return compileApiInfos;
}

// 根据文件列表获取api信息数组
function getFilesApi(files) {
  const fileContentList = [];
  files.forEach(file => {
    let fileContent = fs.readFileSync(file, 'utf-8');
    fileContentList.push({
      fileName: path.basename(file).replace(/.d.ts$/g, '.ts'),
      fileContent: fileContent,
      fileRoot: file,
    });

  });
  const api = parse(fileContentList);
  return api;
}

function getDIffApisWithCompile(newFiles, oldFiles) {
  const newFilesApi = getFilesApi(newFiles);
  const oldFilesApi = getFilesApi(oldFiles);
  // 去掉dtspath后的
  const tmpNewApis = [];
  newFilesApi.forEach(newApi => {
    tmpNewApis.push(JSON.stringify(getApiInfoDeleteDtsPath(newApi)));
  });
  const tmpOldApis = [];
  oldFilesApi.forEach(oldApi => {
    tmpOldApis.push(JSON.stringify(getApiInfoDeleteDtsPath(oldApi)));
  });

  let hasFunTypeNewApis = [];
  let hasFunTypeOldApis = [];
  hasFunTypeNewApis = deleteRepeatApi(tmpOldApis, tmpNewApis, newFilesApi, oldFilesApi).newDiffApiArr;
  hasFunTypeOldApis = deleteRepeatApi(tmpOldApis, tmpNewApis, newFilesApi, oldFilesApi).oldDiffApiArr;

  let newDiffApis = [];
  let oldDiffApis = [];
  newDiffApis = collectSameTypeFun(hasFunTypeNewApis);
  oldDiffApis = collectSameTypeFun(hasFunTypeOldApis);
  const subsystemMap = getSubsystemJson(subsystemDir).subsystemMap;
  const fileNameMap = getSubsystemJson(subsystemDir).fileNameMap;
  const diffApis = [];
  getDiffApisBaseNew(newDiffApis, oldDiffApis, diffApis, subsystemMap, fileNameMap);
  getDiffApisBaseOld(newDiffApis, oldDiffApis, diffApis, subsystemMap, fileNameMap);
  return diffApis;
}

function deleteRepeatApi(oldApis, newApis, newFilesApi, oldFilesApi) {
  let newDiffApiArr = [];
  let oldDiffApiArr = [];
  for (let i = 0; i < newApis.length; i++) {
    const newApi = newApis[i];
    let index = oldApis.indexOf(newApi);
    if (index < 0) {
      let includeTypeApi = addMethodType(newFilesApi[i]);
      newDiffApiArr.push(includeTypeApi);
    }
  }

  for (let i = 0; i < oldApis.length; i++) {
    const oldApi = oldApis[i];
    let index = newApis.indexOf(oldApi);
    if (index < 0) {
      let includeTypeApi = addMethodType(oldFilesApi[i]);
      oldDiffApiArr.push(includeTypeApi);
    }
  }
  return { newDiffApiArr, oldDiffApiArr };
}

function collectSameTypeFun(apiArr) {
  apiArr.forEach(api => {
    let sameNameFun = '';
    // 标记既不是Promise也不是callback的同名函数
    let number = 0;
    let sameNamePromiseText = '';
    apiArr.forEach(newApi => {
      if (api.dtsPath.replace(newDir, '') === newApi.dtsPath.replace(newDir, '') && api.className === newApi.className &&
        api.methodName === newApi.methodName && api.apiType === 'Method' && api.funType === newApi.funType) {
        if (sameNameFun.indexOf(newApi.methodText) < 0 && api.funType === 'callback') {
          sameNameFun += `\n${newApi.methodText}`;
          api.callbackMethodText = sameNameFun;
        } else if (sameNamePromiseText.indexOf(newApi.methodText) < 0 && api.funType === 'Promise') {
          sameNamePromiseText += `\n${newApi.methodText}`;
          api.promiseMethodText = sameNamePromiseText;
        } else if (!api.funType) {
          number++;
          api.note = number;
        }
      }
    });
  });
  return apiArr;
}

function addMethodType(baseApi) {
  let methodContent = `interface test{
              ${baseApi.methodText}
          }`;
  getMethodType(methodContent, filterType);
  if (methodType === 'callback' || methodType === 'Promise') {
    baseApi.funType = methodType;
  }
  return baseApi;
}

function getMethodType(content, callback) {
  ts.transpileModule(content, {
    compilerOptions: {
      'target': ts.ScriptTarget.ES2017,
    },
    fileName: 'index.ets',
    transformers: { before: [callback()] },
  });
}

function filterType() {
  return (context) => {
    methodType = '';
    return (node) => {
      getType(node);
      return node;
    };
    function getType(node) {
      // add function type(callback or Promise)
      if (ts.isFunctionDeclaration(node) || ts.isMethodSignature(node)) {
        getFunType(node);
      }
      return ts.visitEachChild(node, getType, context);
    }
  };
}

function getFunType(node) {
  if (node.type && ts.isTypeReferenceNode(node.type)) {
    methodType = node.type.typeName.escapedText;
  } else if (node.parameters.length > 0) {
    const parameter = node.parameters[node.parameters.length - 1];
    if (parameter.name.escapedText === 'callback') {
      methodType = parameter.name.escapedText;
    }
  } else {
    methodType = '';
  }
}

function collectDeprecatedDiff(newDeprecated, oldDeprecated, startDiffNew, startDiffOld, diffApis, subsystemMap,
  notes, fileNameMap, newApi) {
  flag = '废弃版本有变化';
  diffOld = startDiffOld + '废弃版本：' + oldDeprecated;
  const useinsteadInfo = newApi.useinsteadInfo instanceof Object ? newApi.useinsteadInfo.new : newApi.useinsteadInfo;
  if (newApi.useinsteadInfo) {
    diffNew = `${startDiffNew}废弃版本：${newDeprecated}\n代替接口：${useinsteadInfo}`;
  } else {
    diffNew = startDiffNew + '废弃版本：' + newDeprecated;
  }
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function getDiffApisBaseNew(newDiffApis, oldDiffApis, diffApis, subsystemMap, fileNameMap) {
  const notes = '';
  const diffMethodTextSet = new Set();
  newDiffApis.forEach(newApi => {
    let diffOld = 'NA';
    let diffNew = 'NA';
    const tmpApis = [];

    oldDiffApis.forEach(oldApi => {
      if (newApi.dtsPath.replace(newDir, '') === oldApi.dtsPath.replace(oldDir, '')) {
        tmpApis.push(oldApi);
      }
    });
    if (tmpApis.length === 0) {
      collectNewFileApi(newApi, subsystemMap, notes, fileNameMap, diffApis, diffOld);
    } else {
      if (newApi.apiType === 'import') {
        collectImportDiff(tmpApis, newApi, diffApis, subsystemMap, notes, fileNameMap);
      } else if (newApi.apiType === 'export') {
        collectExportDiff(tmpApis, newApi, diffApis, subsystemMap, notes, fileNameMap);
      } else {
        let oldSameClassApis = handleApiByClassName(tmpApis, newApi, newDiffApis).oldSameClassApi;
        let oldMethodTexts = handleApiByClassName(tmpApis, newApi, newDiffApis).oldMethodTexts;
        collectSameClassDiff(oldSameClassApis, newApi, diffNew, diffOld, diffApis, subsystemMap, fileNameMap, diffMethodTextSet);
        getNewAddApi(oldMethodTexts, diffApis, subsystemMap, fileNameMap, diffMethodTextSet, newApi);
      }
    }
  });
}
function collectSameClassDiff(oldSameClassApis, newApi, diffNew, diffOld, diffApis, subsystemMap, fileNameMap, diffMethodTextSet) {
  const notes = '';
  if (oldSameClassApis.length === 0) {
    flag = '新增';
    if (newApi.methodName === '') {
      diffNew = '模块名: ' + newApi.packageName + '\n类名: ' + newApi.className;
    } else {
      diffNew = '模块名: ' + newApi.packageName + '\n类名: ' + newApi.className +
        '\n方法 or 属性：' + newApi.methodText;
    }
    let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
    diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
  } else {
    oldSameClassApis.forEach(oldApi => {
      if (newApi.methodName === oldApi.methodName && newApi.apiType.toString() === oldApi.apiType.toString()) {
        collectChangePart(newApi, oldApi, diffApis, subsystemMap, fileNameMap, diffMethodTextSet);
      }
    });

  }
}
function getNewAddApi(oldMethodTexts, diffApis, subsystemMap, fileNameMap, diffMethodTextSet, newApi) {
  if (!oldMethodTexts.has(newApi.methodText.replace(/\r|\n|\s+|\,|\;/g, '')) &&
    !diffMethodTextSet.has(newApi.methodText)) {
    const notes = '';
    const flag = '新增';
    const diffNew = '类名：' + newApi.className + '\n方法or属性：' + newApi.methodText;
    const diffOld = 'NA';
    let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
    diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
  }
}
function collectChangePart(newApi, oldApi, diffApis, subsystemMap, fileNameMap, diffMethodTextSet) {
  let startDiffOld = '';
  let startDiffNew = '';
  const NOTE_NUMBER = 2;
  if (newApi.methodName === '') {
    startDiffOld = '类名：' + oldApi.className + '\n';
    startDiffNew = '类名：' + newApi.className + '\n';
  } else {
    startDiffOld = '类名：' + oldApi.className + '\n方法 or 属性：' + oldApi.methodText + '\n';
    startDiffNew = '类名：' + newApi.className + '\n方法 or 属性：' + newApi.methodText + '\n';
  }
  if (isCallbackTypeFun(newApi, oldApi, 'callback')) {
    diffMethodTextSet.add(newApi.methodText);
    collectMethodTextDiff(oldApi, newApi, startDiffNew, startDiffOld, diffApis, newApi.callbackMethodText,
      oldApi.callbackMethodText, subsystemMap, fileNameMap);
  }
  if (isPromiseTypeFun(newApi, oldApi, 'Promise')) {
    diffMethodTextSet.add(newApi.methodText);
    collectMethodTextDiff(oldApi, newApi, startDiffNew, startDiffOld, diffApis, newApi.promiseMethodText,
      oldApi.promiseMethodText, subsystemMap, fileNameMap);
  }
  if (!newApi.funType && !oldApi.funType && newApi.methodText !== oldApi.methodText && newApi.note < NOTE_NUMBER) {
    diffMethodTextSet.add(newApi.methodText);
    collectMethodTextDiff(oldApi, newApi, startDiffNew, startDiffOld, diffApis, newApi.methodText,
      oldApi.methodText, subsystemMap, fileNameMap);
  }
  if (newApi.methodText === oldApi.methodText) {
    collectNoteDiff(newApi.version, oldApi.version, newApi.deprecated, oldApi.deprecated, newApi.errorCode,
      oldApi.errorCode, newApi.sysCap, oldApi.sysCap, newApi.isSystemApi, oldApi.isSystemApi, newApi.permission,
      oldApi.permission, newApi.model, oldApi.model, newApi.typeInfo, oldApi.typeInfo, startDiffNew, startDiffOld,
      diffApis, subsystemMap, fileNameMap, newApi);
  }

}
function isCallbackTypeFun(newApi, oldApi, funType) {
  if (newApi.funType === funType && oldApi.funType === funType &&
    newApi.callbackMethodText !== oldApi.callbackMethodText) {
    return true;
  } else {
    return false;
  }
}
function isPromiseTypeFun(newApi, oldApi, funType) {
  if (newApi.funType === funType && oldApi.funType === funType &&
    newApi.promiseMethodText !== oldApi.promiseMethodText) {
    return true;
  } else {
    return false;
  }
}

function collectNoteDiff(newVersion, oldVersion, newDeprecated, oldDeprecated, newErrorCode, oldErrorCode, newSyscap,
  oldSyscap, newIsSystemApi, oldIsSystemApi, newPermission, oldPermission, newModel, oldModel, newTypeInfo,
  oldTypeInfo, startDiffNew, startDiffOld, diffApis, subsystemMap, fileNameMap, newApi) {
  const notes = '';
  if (newVersion !== oldVersion) {
    collectVersionDiff(newVersion, oldVersion, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newDeprecated !== oldDeprecated) {
    collectDeprecatedDiff(newDeprecated, oldDeprecated, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newErrorCode !== oldErrorCode) {
    collectErrorCodeDiff(newErrorCode, oldErrorCode, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newSyscap !== oldSyscap) {
    collectSyscapDiff(newSyscap, oldSyscap, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newIsSystemApi !== oldIsSystemApi) {
    collectSystemApiDiff(newIsSystemApi, oldIsSystemApi, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newPermission !== oldPermission) {
    collectPermissionDiff(newPermission, oldPermission, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newModel !== oldModel) {
    collectModelDiff(newModel, oldModel, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
  if (newTypeInfo !== oldTypeInfo) {
    collectTypeDiff(newTypeInfo, oldTypeInfo, startDiffNew, startDiffOld,
      diffApis, subsystemMap, notes, fileNameMap, newApi);
  }
}

function collectTypeDiff(newType, oldType, startDiffNew, startDiffOld, diffApis, subsystemMap, notes, fileNameMap, newApi) {
  let flag = '';
  if (oldType !== newType) {
    flag = 'type有变化';
  }
  if (flag) {
    diffOld = startDiffOld + 'type：' + oldType;
    diffNew = startDiffNew + 'type：' + newType;
    let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
    diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
  }
}

function collectNewFileApi(newApi, subsystemMap, notes, fileNameMap, diffApis, diffOld) {
  const flag = '新增';
  let diffNew = '';
  if (newApi.apiType === 'import') {
    diffNew = '模块名: ' + newApi.packageName + '\nimport 信息: ' + newApi.headimport;
  } else if (newApi.apiType === 'export') {
    diffNew = '模块名: ' + newApi.packageName + '\nexport 信息: ' + newApi.endexport;
  } else if (newApi.methodName === '') {
    diffNew = '模块名: ' + newApi.packageName + '\n类名: ' + newApi.className;
  } else {
    diffNew = '模块名: ' + newApi.packageName + '\n类名: ' + newApi.className + '\n方法 or 属性: ' + newApi.methodText;
  }
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function collectImportDiff(tmpApis, newApi, diffApis, subsystemMap, notes, fileNameMap) {
  const tmpApis2 = [];
  tmpApis.forEach(oldApi => {
    if (oldApi.apiType === 'import' && newApi.headimport === oldApi.headimport) {
      tmpApis2.push(oldApi);
    }
  });

  if (tmpApis2.length === 0) {
    flag = '新增';
    diffNew = '模块名: ' + newApi.packageName + '\nimport 信息: ' + newApi.headimport;
  }
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function collectExportDiff(tmpApis, newApi, diffApis, subsystemMap, notes, fileNameMap) {
  const tmpApis3 = [];
  tmpApis.forEach(oldApi => {
    if (oldApi.apiType === 'export' && newApi.endexport === oldApi.endexport) {
      tmpApis3.push(oldApi);
    }
  });
  if (tmpApis3.length === 0) {
    flag = '新增';
    diffNew = '模块名: ' + newApi.packageName + '\nexport 信息: ' + newApi.endexport;
  }
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function handleApiByClassName(tmpApis, newApi, newDiffApis) {
  const oldSameClassApi = [];
  const newSameClassApi = [];
  const oldMethodTexts = new Set([]);
  const newMethodTexts = new Set([]);
  let equalClassName = 'N/A';
  tmpApis.forEach(oldApi => {
    if (newApi.className === oldApi.className) {
      oldSameClassApi.push(oldApi);
      equalClassName = oldApi.className;
      oldMethodTexts.add(oldApi.methodText.replace(/\r|\n|\s+|\,|\;/g, ''));
    }
  });
  newDiffApis.forEach(apiText => {
    if (apiText.className === equalClassName) {
      newMethodTexts.add(apiText.methodText.replace(/\r|\n|\s+|\,|\;/g, ''));
      newSameClassApi.push(apiText);
    }
  });
  return { oldSameClassApi, oldMethodTexts, newMethodTexts };
}

function collectVersionDiff(newVersion, oldVersion, startDiffNew, startDiffOld, diffApis,
  subsystemMap, notes, fileNameMap, newApi) {
  flag = '起始版本有变化';
  diffOld = startDiffOld + '起始版本：' + oldVersion;
  diffNew = startDiffNew + '起始版本：' + newVersion;
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function collectModelDiff(newModel, oldModel, startDiffNew, startDiffOld, diffApis,
  subsystemMap, notes, fileNameMap, newApi) {
  flag = 'model有变化';
  diffOld = startDiffOld + 'model:' + oldModel;
  diffNew = startDiffNew + 'model:' + newModel;
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function collectPermissionDiff(newPermission, oldPermission, startDiffNew, startDiffOld, diffApis,
  subsystemMap, notes, fileNameMap, newApi) {
  flag = getPermissionFlag(oldPermission, newPermission);
  if (flag !== '格式变化') {
    diffOld = startDiffOld + '权限:' + oldPermission;
    diffNew = startDiffNew + '权限:' + newPermission;
    let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
    diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
  }
}

function collectMethodTextDiff(oldApi, newApi, startDiffNew, startDiffOld, diffApis, newMethodText, oldMethodText,
  subsystemMap, fileNameMap) {
  flag = getMethodFlag(oldMethodText, newMethodText);
  const note = '去重';
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  if (flag === '函数有变化') {
    diffOld = startDiffOld;
    diffNew = startDiffNew;
    diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, note, fileNameMap));
  }
}

function collectErrorCodeDiff(newErrorCode, oldErrorCode, startDiffNew, startDiffOld, diffApis, subsystemMap, notes,
  fileNameMap, newApi) {
  flag = oldErrorCode === 'N/A' ? '新增(错误码)' : 'API修改(错误码)';
  if (flag === '新增(错误码)') {
    diffOld = 'NA';
  } else if (flag === 'API修改(错误码)') {
    diffOld = startDiffOld + '错误码内容：' + oldErrorCode;
  }
  diffNew = startDiffNew + '错误码内容:' + newErrorCode;
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function collectSyscapDiff(newSyscap, oldSyscap, startDiffNew, startDiffOld, diffApis, subsystemMap, notes,
  fileNameMap, newApi) {
  flag = 'SysCap有变化';
  diffOld = startDiffOld + 'SysCap:' + oldSyscap;
  diffNew = startDiffNew + 'SysCap:' + newSyscap;
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function collectSystemApiDiff(newIsSystemApi, oldIsSystemApi, startDiffNew, startDiffOld, diffApis, subsystemMap,
  notes, fileNameMap, newApi) {
  flag = '访问级别有变化';
  diffOld = startDiffOld + '访问级别：' + oldIsSystemApi;
  diffNew = startDiffNew + '访问级别：' + newIsSystemApi;
  let sysCapInfo = getSubsystemBySyscap(newApi, newApi.sysCap);
  diffApis.push(getApiInfoWithFlag(newApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
}

function getMethodFlag(methodTextOld, methodTextNew) {
  let methodTextOlds = methodTextOld.replace(/\r|\n|\s+|\,|\;/g, '');
  let methodTextNews = methodTextNew.replace(/\r|\n|\s+|\,|\;/g, '');
  if (methodTextOlds === methodTextNews) {
    return '函数格式变化';
  } else {
    return '函数有变化';
  }
}

function getPermissionFlag(permissionOld, permissionNew) {
  let permissionOlds = permissionOld.replace(/\r|\n|\s+|\.|\//g, '');
  let permissionNews = permissionNew.replace(/\r|\n|\s+|\.|\//g, '');
  if (permissionOlds === permissionNews) {
    return '格式变化';
  } else if (permissionOld === 'N/A') {
    return '新增(权限)';
  } else if (permissionNew === 'N/A') {
    return '删除(权限)';
  } else {
    return '权限有变化';
  }
}

function getDiffApisBaseOld(newDiffApis, oldDiffApis, diffApis, subsystemMap, fileNameMap) {
  const notes = '';
  oldDiffApis.forEach(oldApi => {
    let flag = '';
    let diffOld = '';
    let diffNew = 'NA';
    const tmpApis = [];
    newDiffApis.forEach(newApi => {
      if (oldApi.dtsPath.replace(oldDir, '') === newApi.dtsPath.replace(newDir, '')) {
        tmpApis.push(newApi);
      }
    });
    if (tmpApis.length === 0) {
      flag = deleteFileApi(oldApi, flag, diffOld).flag;
      diffOld = deleteFileApi(oldApi, flag, diffOld).diffOld;
    } else {
      if (oldApi.apiType === 'import') {
        flag = deleteImportApi(flag, diffOld, tmpApis, oldApi).flag;
        diffOld = deleteImportApi(flag, diffOld, tmpApis, oldApi).diffOld;
      } else if (oldApi.apiType === 'export') {
        flag = deleteExportApi(flag, diffOld, tmpApis, oldApi).flag;
        diffOld = deleteExportApi(flag, diffOld, tmpApis, oldApi).diffOld;
      } else {
        flag = collectDeleteApis(tmpApis, oldApi, flag, diffOld).flag;
        diffOld = collectDeleteApis(tmpApis, oldApi, flag, diffOld).diffOld;
      }
    }
    if (flag !== '') {
      let sysCapInfo = getSubsystemBySyscap(oldApi, oldApi.sysCap);
      diffApis.push(getApiInfoWithFlag(oldApi, flag, diffOld, diffNew, subsystemMap, sysCapInfo, notes, fileNameMap));
    }
  });
}

function collectDeleteApis(tmpApis, oldApi, flag, diffOld) {
  const newSameClassApis = [];
  tmpApis.forEach(newApi => {
    if (oldApi.className === newApi.className) {
      newSameClassApis.push(newApi);
    }
  });
  if (newSameClassApis.length === 0) {
    flag = '删除';
    if (oldApi.methodName === '') {
      diffOld = '模块名: ' + oldApi.packageName + '\n类名: ' + oldApi.className;
    } else {
      diffOld = '模块名: ' + oldApi.packageName + '\n类名: ' + oldApi.className + '\n方法 or 属性：' + oldApi.methodText;
    }
  } else {
    let count = 0;
    newSameClassApis.forEach(newApi => {
      if (oldApi.methodName === newApi.methodName && oldApi.apiType.toString() === newApi.apiType.toString()) {
        count++;
      }
    });

    if (count === 0) {
      flag = '删除';
      if (oldApi.methodName === '') {
        diffOld = '模块名：' + oldApi.packageName + '\n类名:' + oldApi.className;
      } else {
        diffOld = '模块名：' + oldApi.packageName + '\n类名:' + oldApi.className + '\n方法 or 属性:' + oldApi.methodText;
      }
    }
  }
  return { flag, diffOld };
}

function deleteImportApi(flag, diffOld, tmpApis, oldApi) {
  const tmpApis2 = [];
  tmpApis.forEach(newApi => {
    if (newApi.apiType === 'import' && newApi.headimport === oldApi.headimport) {
      tmpApis2.push(newApi);
    }
  });

  if (tmpApis2.length === 0) {
    flag = '删除';
    diffOld = '模块名: ' + oldApi.packageName + '\nimport 信息: ' + oldApi.headimport;
  }
  return { flag, diffOld };
}

function deleteExportApi(flag, diffOld, tmpApis, oldApi) {
  const tmpApis3 = [];
  tmpApis.forEach(newApi => {
    if (newApi.apiType === 'export' && newApi.endexport === oldApi.endexport) {
      tmpApis3.push(newApi);
    }
  });
  if (tmpApis3.length === 0) {
    flag = '删除';
    diffOld = '模块名: ' + oldApi.packageName + '\nexport 信息: ' + oldApi.endexport;
  }
  return { flag, diffOld };
}

function deleteFileApi(oldApi, flag, diffOld) {
  flag = '删除';
  if (oldApi.apiType === 'import') {
    diffOld = '模块名: ' + oldApi.packageName + '\nimport 信息: ' + oldApi.headimport;
  } else if (oldApi.apiType === 'export') {
    diffOld = '模块名: ' + oldApi.packageName + '\nexport 信息: ' + oldApi.endexport;
  } else if (oldApi.methodName === '') {
    diffOld = '模块名: ' + oldApi.packageName + '\n类名: ' + oldApi.className;
  } else {
    diffOld = '模块名: ' + oldApi.packageName + '\n类名: ' + oldApi.className + '\n方法 or 属性：' + oldApi.methodText;
  }
  return { flag, diffOld };
}

// 输出新旧版本所有api对比结果
async function exportDiffApiInfo(exportType, compileApiInfos, exportFileName) {
  if (exportType === 'excel') {
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('api差异', { viers: [{ xSplit: 1 }] });
    sheet.getRow(1).values = ['操作标记*', '差异项-旧版本', '差异项-新版本', 'd.ts文件', '归属子系统'];
    for (let i = 0; i < compileApiInfos.length; i++) {
      let apiData = compileApiInfos[i];
      let fileName = apiData.dtsPath ? path.basename(apiData.dtsPath) : apiData.packageName;
      const ADD_NUMBER = 2;
      sheet.getRow(i + ADD_NUMBER).values = [apiData.flag, apiData.diffOld, apiData.diffNew, fileName,
        apiData.subsystem];
    }
    const buffer = await workbook.xlsx.writeBuffer();
    fs.writeFile(exportFileName, buffer, function (err) {
      if (err) {
        return;
      }
    });
  } else if (exportType === 'json') {
    fs.writeFile(exportFileName, JSON.stringify(compileApiInfos), function (err) {
      if (err) {
        console.log('Write failed:' + err);
        return;
      }
      console.log(exportFileName + 'Write completed.');
    });
  }
}

function exportDiffMd(subsystem, diffInfos) {
  let finalContent = '| 操作 | 旧版本 | 新版本 | d.ts文件 |\n' + '| ---- | ------ | ------ | -------- |\n';
  for (let i = 0; i < diffInfos.length; i++) {
    let apiData = diffInfos[i];
    let fileName = apiData.dtsPath ? path.basename(apiData.dtsPath) : apiData.packageName;
    const oldData = apiData.diffOld.replace(/\r|\n/g, '<br>').replace(/\|/g, '\\|').replace(/\<(?!br>)/g, '\\<');
    const newData = apiData.diffNew.replace(/\r|\n/g, '<br>').replace(/\|/g, '\\|').replace(/\<(?!br>)/g, '\\<');
    finalContent += `|${apiData.flag}|${oldData}|${newData}|${fileName}|\n`;
  }
  const mdFilesDir = `${__dirname.replace('src', '')}diff合集`;
  if (!fs.existsSync(mdFilesDir)) {
    fs.mkdirSync('../diff合集');
  }

  fs.writeFile(`../diff合集/js-apidiff-${subsystem}.md`, finalContent, function (err) {
    if (err) {
      console.log('WRITE FAILED:::', err);
      return;
    }
    console.log('WRITE SUCCESSED');
  });

}

function diffBySbusystem(compileApiInfos) {
  let filePath = __dirname.replace('\\src', '') + '\\subsystem.json';
  let subsystemArr = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  let flagArr = ['新增', '删除', 'model有变化', '访问级别有变化', '废弃版本有变化', '起始版本有变化', '权限有变化',
    '删除(权限)', '新增(错误码)', '新增(权限)', '错误码有变化', 'SysCap有变化', '函数有变化'];
  subsystemArr.forEach(subsystem => {
    let diffInfos = [];
    compileApiInfos.forEach(api => {
      if (subsystem.subsystem === api.subsystem) {
        diffInfos.push(api);
      }
    });
    if (diffInfos.length !== 0) {
      const sortDiffInfos = [];
      flagArr.forEach(flag => {
        diffInfos.forEach(diffInfo => {
          if (diffInfo.flag === flag) {
            sortDiffInfos.push(diffInfo);
          }
        });
      });
      exportDiffMd(subsystem.fileName, sortDiffInfos);
    }

  });
}
// 读取路径下所有的zip文件路径
function readZipFile(dir, zipFiles) {
  try {
    const files = fs.readdirSync(dir);
    files.forEach(element => {
      const filePath = path.join(dir, element);
      const status = fs.statSync(filePath);
      if (status.isDirectory()) {
        readZipFile(filePath, zipFiles);
      } else {
        if (filePath.endsWith('.zip')) {
          zipFiles.push(filePath);
        }
      }
    });
  } catch (error) {
    console.error('ETS ERROR:' + error);
  }
}

function unCompressAllZipFilesAndCompile(newDir, oldDir) {
  const zipFiles = [];
  readZipFile(newDir, zipFiles);
  readZipFile(oldDir, zipFiles);
  let count = 0;
  let countfile = 0;
  zipFiles.forEach(async element => {
    let filePath = element.replace(path.basename(element), '');
    compressing.zip.uncompress(element, filePath).then((data) => {
      console.log('uncompress success:', data, '--' + element);
      count++;
      if ((count + countfile) === zipFiles.length) {
        compileAndExportToFile();
      }
    }).catch(error => {
      console.log(('uncompress error:', error));
    });
  });
}

function compileAndExportToFile() {
  const newFiles = [];
  const oldFiles = [];
  readFile(oldDir, oldFiles);
  readFile(newDir, newFiles);
  let diffApis = getDIffApisWithCompile(newFiles, oldFiles);
  let noRepeatDiffApi = [];
  let diffApisSet = new Set();
  diffApis.map(api => diffApisSet.add(JSON.stringify(api)));
  diffApisSet.forEach(item => {
    noRepeatDiffApi.push(JSON.parse(item));
  });
  for (let i = 0; i < allMergeData.length; i++) {
    for (let j = 0; j < noRepeatDiffApi.length; j++) {
      if (allMergeData[i].packageName === noRepeatDiffApi[j].packageName && noRepeatDiffApi[j].flag === '删除' &&
        allMergeData[i].diffOld === noRepeatDiffApi[j].methodText) {
        noRepeatDiffApi.splice(j, 1);
        j--;
      } else if (allMergeData[i].packageName === noRepeatDiffApi[j].packageName &&
        noRepeatDiffApi[j].flag === '新增' && allMergeData[i].diffNew === noRepeatDiffApi[j].methodText) {
        noRepeatDiffApi.splice(j, 1);
        j--;
      }

    }

  }
  let afterMergeData = noRepeatDiffApi.concat(allMergeData);
  exportDiffApiInfo('excel', afterMergeData, 'Js_Api_Diff.xlsx');
  diffBySbusystem(afterMergeData);
}

const subsystemDir = __dirname.replace('\\src', '') + '\\subsystem.json';
const urlObject = fs.readFileSync(__dirname.replace('\\src', '') + '\\url.json', 'utf-8');
const oldDir = JSON.parse(urlObject).oldDir;
const newDir = JSON.parse(urlObject).newDir;
unCompressAllZipFilesAndCompile(newDir, oldDir);
