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

const ts = require('typescript');
const { listApiDeclarationFiles } = require('./util');
const { StatusCode, DiffReporter } = require('./reporter');
const { ApiCollector } = require('./api_collector');
const { ApiDigestInfo } = require('./api_data');
const { JSDocDiffer } = require('./jsdoc_diff');

/**
 * 循环搜集API信息
 * 
 * @param {string[]} files 
 * @param {string} rootDir 
 * @returns {Map} Map
 */
function collectApiDigestInfos(files, rootDir) {
  const apiMap = new Map();
  files.forEach(filePath => {
    ApiCollector.collectApi(filePath, rootDir, apiMap);
  });
  return apiMap;
}

/**
 * 解析API，对比新旧版本的SDK集合筛选出变化。
 * 
 * @param {string[]} newFiles 新版本API文件列表
 * @param {string[]} oldFiles 旧版本API文件列表
 * @param {string} oldDir 旧版本SDK根目录
 * @param {string} newDir 新版本SDK根目录
 * @returns {Map}
 */
function getApiDiffs(newFiles, oldFiles, oldDir, newDir) {
  const newApiInfos = collectApiDigestInfos(newFiles, newDir);
  const oldApiInfos = collectApiDigestInfos(oldFiles, oldDir);
  const diffReporter = new DiffReporter();
  collectAllApiDiffs(newApiInfos, oldApiInfos, diffReporter, oldDir, newDir);
  return diffReporter.getResults();
}

function exportDiffInfo(newFiles, oldFiles, newDir, oldDir) {
  const newApiInfos = collectApiDigestInfos(newFiles, newDir);
  const oldApiInfos = collectApiDigestInfos(oldFiles, oldDir);
  const diffReporter = new DiffReporter();
  collectAllApiDiffs(newApiInfos, oldApiInfos, diffReporter, oldDir, newDir);
  return diffReporter.getDiffInfos();
}

exports.exportDiffInfo = exportDiffInfo;

/**
 * 比对API摘要信息获取差异。
 * @example API集合的数据结构如下:
 * { packageName : Map }
 *                  |
 *      { className : { type: ApiDigestInfo, children: Map } }
 *                                                      |
 *                                             { apiName : Map }
 *                                                          |
 *                                                { signature : ApiDigestInfo[] }
 * 
 *  针对上述数据结构, 比对的策略如下:
 *  优先遍历旧SDK API, 因为相对新版本SDK其API数量较少。
 *  1. 比对 packageName, 新SDK中没有则可能为删除或调整目录结构
 *  2. 比对 className, 新SDK中没有则可能为删除或结构调整
 *  3. 比对 apiSignature, 新SDK中没有则可能为删除或者调整
 *  4. 上述路径完全匹配时，则API定义没有变动，再比JSDoc修改
 *  5. 第 4 步结束后从新SDK集合中删除, 最后新SDK集合中剩余的即新增的API
 *  以上策略需要进一步细化, 尽可能推断出API的具体变化细节。
 * 
 * @param {Map} newApiMap 新SDK API集合
 * @param {Map} oldApiMap 旧SDK API集合
 * @param {DiffReporter} diffReporter 差异报告
 * @param {string} oldDir 旧SDK根目录
 * @param {string} newDir 新SDK根目录
 */
function collectAllApiDiffs(newApiMap, oldApiMap, diffReporter, oldDir, newDir) {
  // 遍历旧sdk
  oldApiMap.forEach((oldPackageMap, packageName) => {
    collectApiDiffFromPackageMap(oldPackageMap, packageName, newApiMap, {
      diffReporter: diffReporter,
      oldDir: oldDir,
      newDir: newDir,
    });
  });
  newApiMap.forEach((newPackageMap, _) => {
    collectAllApiDiffFromPackageMap(newPackageMap, diffReporter);
  });
}

function collectAllApiDiffFromPackageMap(newPackageMap, diffReporter) {
  newPackageMap.forEach((newClassMap, _) => {
    newClassMap.children.forEach((apisMap, _) => {
      apisMap.forEach((apis, _) => {
        diffReporter.addNewApi(apis[0], getSyscap(apis[0]));
        const diffInfo = formatDiffInfo(apis[0], StatusCode.NEW_API, '', apis[0].getRawText(), '', apis[0].node, getSyscap(apis[0]));
        diffReporter.addDiffInfo(diffInfo);
      });
    });
  });
}

/**
 * 判断是否有相同的 d.ts 声明文件
 * 
 * @param {Map} oldPackageMap d.ts内部的API集合
 * @param {string} packageName d.ts与SDK根目录的相对路径
 * @param {Map} newApiMap 新SDK的所有API集合
 * @param {Object} ext 扩展参数
 */
function collectApiDiffFromPackageMap(oldPackageMap, packageName, newApiMap, ext) {
  if (!newApiMap.has(packageName)) {
    // dts文件删除
    let dtsPath;
    oldPackageMap.forEach((classNameMap, _) => {
      collectApiDiffFromPackageMapClass(classNameMap, ext);
      dtsPath = classNameMap.type.path;
    });
    ext.diffReporter.addDeletedPackage(packageName, dtsPath);
  } else {
    // 比较相同dts文件
    const newPackageMap = newApiMap.get(packageName);
    oldPackageMap.forEach((oldClassMap, className) => {
      collectApiDiffFromClassMap(oldClassMap, className, newPackageMap, ext);
    });
  }
}

function collectApiDiffFromPackageMapClass(classNameMap, ext) {
  classNameMap.children.forEach((apisMap, _) => {
    apisMap.forEach((apis, _) => {
      ext.diffReporter.addDeletedApi(apis[0], getSyscap(apis[0]));
      const diffInfo = formatDiffInfo(apis[0], StatusCode.DELETE, apis[0].getRawText(), '',
        apis[0].node, '', getSyscap(apis[0]));
      ext.diffReporter.addDiffInfo(diffInfo);
    });
  });
}

function getSyscap(api) {
  let curApi = api;
  let syscap = '';
  if (api.packageName === 'ArkUI') {
    return 'ArkUI';
  }
  while (curApi && !ts.isSourceFile(curApi.node)) {
    const jsdoc = curApi.jsdoc ? curApi.jsdoc[curApi.jsdoc.length - 1] : [];

    if (!jsdoc) {
      return syscap;
    }

    const jsdocTagItem = jsdoc.tags ? jsdoc.tags : [];
    for (let i = 0; i < jsdocTagItem.length; i++) {
      const tagInfo = jsdocTagItem[i];
      if (tagInfo.tag === 'syscap') {
        syscap = tagInfo.name;
      }
    }

    if (syscap) {
      return syscap;
    }
    curApi = curApi.parent;
  }

  if (ts.isSourceFile(curApi.node)) {
    const fileContent = curApi.node.getFullText();
    if (/\@syscap\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(fileContent)) {
      fileContent.replace(/\@syscap\s*((\w|\.|\/|\{|\@|\}|\s)+)/g, sysCapInfo => {
        syscap = sysCapInfo.replace(/\@syscap/g, '').trim();
      });
    }
  }
  return syscap;
}

/**
 * 判断是否有有相同的类型定义(class, interface, enum)
 * 
 * @param {Object} oldClassApi 旧SDK类型内部的API集合
 * @param {string} packageName d.ts与SDK根目录的相对路径
 * @param {string} className 类型名称
 * @param {Map} newPackageMap 新版本d.ts内部的API集合
 * @param {Object} ext 扩展参数
 */
function collectApiDiffFromClassMap(oldClassApi, className, newPackageMap, ext) {
  if (!newPackageMap.has(className)) {
    // 类被删除
    const typeApi = oldClassApi.type;
    ext.diffReporter.addChangedApi({
      api: typeApi,
      statusCode: StatusCode.DELETE_CLASS,
      oldMessage: '',
      newMessage: '',
      oldNode: '',
      newNode: '',
      syscap: getSyscap(oldClassApi.type),
    });
    oldClassApi.children.forEach((apisMap, _) => {
      apisMap.forEach((apis, _) => {
        ext.diffReporter.addDeletedApi(apis[0], getSyscap(apis[0]));
        const diffInfo = formatDiffInfo(apis[0], StatusCode.DELETE, apis[0].getRawText(), '',
          apis[0].node, '', getSyscap(apis[0]));
        ext.diffReporter.addDiffInfo(diffInfo);
      });
    });
  } else {
    // 有相同的类
    const newClassApi = newPackageMap.get(className);
    collectClassApiDiffs(oldClassApi, newClassApi, ext);
    oldClassApi.children.forEach((signatureMap, apiName) => {
      collectApiDiffFromApiNameMap(signatureMap, apiName, newClassApi.children, ext);
    });
  }
}

/**
 * 
 * @param {Map} oldSignatureMap 
 * @param {string} apiName 
 * @param {Map} newClassMap 
 * @param {Object} ext 
 */
function collectApiDiffFromApiNameMap(oldSignatureMap, apiName, newClassMap, ext) {
  if (!newClassMap.has(apiName)) {
    // 方法被删除
    oldSignatureMap.forEach((oldApis, _) => {
      ext.diffReporter.addDeletedApi(oldApis[0], getSyscap(oldApis[0]));
    });
  } else {
    const newSignatureMap = newClassMap.get(apiName);
    const sameApiNameNumber = oldSignatureMap.size;
    const sameSignatureSet = new Set();
    oldSignatureMap.forEach((oldApis, apiSignautre) => {
      collectApiDiffFromApiSignatureMap(oldApis, apiSignautre, newSignatureMap, ext, sameApiNameNumber, sameSignatureSet);
    });

    sameSignatureSet.forEach(sameSignature => {
      oldSignatureMap.delete(sameSignature);
    });

    oldSignatureMap.forEach((oldApis, _) => {
      if (newSignatureMap.size === 0) {
        // 同名函数，方法被删除
        ext.diffReporter.addDeletedApi(oldApis[0], getSyscap(oldApis[0]));
      } else {
        getFunctionDiff(oldApis, newSignatureMap, ext, sameApiNameNumber);
      }
    });

  }
}

function collectClassApiDiffs(oldClassApi, newClassApi, ext) {
  const oldClassDigestInfo = oldClassApi.type;
  const newClassDigestInfo = newClassApi.type;
  if (oldClassDigestInfo && newClassDigestInfo) {
    if (oldClassDigestInfo.getApiSignature() !== newClassDigestInfo.getApiSignature()) {
      ext.diffReporter.addChangedApi({
        api: newClassDigestInfo,
        statusCode: StatusCode.CLASS_CHANGES,
        oldMessage: oldClassDigestInfo.getRawText(),
        newMessage: newClassDigestInfo.getRawText(),
        hint: '',
      });
    } else {
      collectJSDocDiffs(oldClassDigestInfo, newClassDigestInfo, ext.diffReporter);
    }
  }
}

/**
 * 判断是否有相同的API签名
 * 
 * @param {Map} oldApis 旧版本特定类型的所有API集合
 * @param {string} apiSignautre API 签名
 * @param {Map} newClassMap 新版本特定类型内部API集合
 * @param {Object} ext 扩展参数
 * @param {number} sameApiNameNumber 名字相同的API个数
 */
function collectApiDiffFromApiSignatureMap(oldApis, apiSignautre, newClassMap, ext, sameApiNameNumber, sameSignatureSet) {
  if (newClassMap.has(apiSignautre)) {
    const newApis = newClassMap.get(apiSignautre);
    collectJSDocDiffs(oldApis[0], newApis[0], ext.diffReporter);
    newClassMap.delete(apiSignautre);
    sameSignatureSet.add(apiSignautre);
  }
}

/**
 * 判断函数有变化的场景
 * 
 * @param {Array} oldApis 旧版本API的摘要信息 
 * @param {Map} newClassMap 与旧版本API名字相同的新版本API集合
 * @param {Object} ext 
 * @param {number} sameApiNameNumber 与旧版本API名字相同的新版本API个数
 */
function getFunctionDiff(oldApis, newClassMap, ext, sameApiNameNumber) {
  if (sameApiNameNumber === 1) {
    newClassMap.forEach((apiDigestInfo, apiSignautre) => {
      const diffInfo = formatDiffInfo(oldApis[0], StatusCode.FUNCTION_CHANGES, oldApis[0].getRawText(), apiDigestInfo[0].getRawText(),
        oldApis[0].node, apiDigestInfo[0].node, getSyscap(apiDigestInfo[0]));
      ext.diffReporter.addChangedApi(diffInfo);
      ext.diffReporter.addDiffInfo(diffInfo);
      collectJSDocDiffs(oldApis[0], apiDigestInfo[0], ext.diffReporter);
      newClassMap.delete(apiSignautre);
    });
  } else if (sameApiNameNumber > 1) {
    let oldApiType = judgeApiType(oldApis[0].getAstNode());
    let newApiTypeMap = new Map();
    getEveryNewApiType(newClassMap, newApiTypeMap);
    if (newApiTypeMap.get(oldApiType) !== undefined && newApiTypeMap.get(oldApiType).size > 1) {
      ext.diffReporter.addDeletedApi(oldApis[0], getSyscap(oldApis[0]));
      const diffInfo = formatDiffInfo(oldApis[0], StatusCode.DELETE, oldApis[0].getRawText(), '',
        oldApis[0].node, '', getSyscap(oldApis[0]));
      ext.diffReporter.addDiffInfo(diffInfo);
    } else if (newApiTypeMap.get(oldApiType) !== undefined && newApiTypeMap.get(oldApiType).size === 1) {
      const oldMessage = oldApis[0].getRawText();
      const newApi = newClassMap.get(...newApiTypeMap.get(oldApiType))[0];
      const newMessage = newApi.getRawText();
      const newNode = newApi.node;
      const syscap = getSyscap(newClassMap.get(...newApiTypeMap.get(oldApiType))[0]);
      const diffInfo = formatDiffInfo(oldApis[0], StatusCode.FUNCTION_CHANGES, oldMessage, newMessage, oldApis[0].node, newNode, syscap);
      ext.diffReporter.addChangedApi(diffInfo);
      ext.diffReporter.addDiffInfo(diffInfo);
      collectJSDocDiffs(oldApis[0], newApi, ext.diffReporter);
      newClassMap.delete(...newApiTypeMap.get(oldApiType));
    }
  }
}

function formatDiffInfo(api, statusCode, oldMessage, newMessage, oldNode, newNode, syscap) {
  return {
    api: api,
    statusCode: statusCode,
    oldMessage: oldMessage,
    newMessage: newMessage,
    hint: '',
    oldNode: oldNode,
    newNode: newNode,
    syscap: syscap,
  };
}

/**
 * 
 * @param {Map} newClassMap 与旧版本API名字相同的新版本API集合
 * @param {Map} newApiTypeMap 用于存放每一个新版本API的类型和API签名
 *                   |
 *     key：API类型，value：同种类型的API签名所构成的Set集合
 */
function getEveryNewApiType(newClassMap, newApiTypeMap) {
  const callbackApiSignautreSet = new Set();
  const promiseApiSignautreSet = new Set();
  const otherTypeApiSignautreSet = new Set();

  newClassMap.forEach((apiDigestInfo, apiSignautre) => {
    let apiType = judgeApiType(apiDigestInfo[0].getAstNode());
    if (apiType === 'callback') {
      callbackApiSignautreSet.add(apiSignautre);
      newApiTypeMap.set(apiType, callbackApiSignautreSet);
    } else if (apiType === 'Promise') {
      promiseApiSignautreSet.add(apiSignautre);
      newApiTypeMap.set(apiType, promiseApiSignautreSet);
    } else if (apiType === 'other') {
      otherTypeApiSignautreSet.add(apiSignautre);
      newApiTypeMap.set(apiType, otherTypeApiSignautreSet);
    }
  });
}

/**
 * 判断旧API的类型（Promise/callback/other）
 * 
 * @param {ts.node} node 
 * @returns {string}
 */
function judgeApiType(node) {
  const parameters = node.parameters ? node.parameters : [];
  let apiType = 'other';
  parameters.forEach(param => {
    if (param.type && param.type.typeName && param.type.typeName.escapedText === 'AsyncCallback') {
      apiType = 'callback';
    }
  });
  if (node.type && node.type.typeName && node.type.typeName.escapedText === 'Promise') {
    apiType = 'Promise';
  }
  return apiType;
}

/**
 * API完全相同，比对JSDoc修改。
 * 
 * @param {ApiDigestInfo} oldApi 旧API
 * @param {ApiDigestInfo} newApi 新API
 * @param {DiffReporter} diffReporter 差异报告
 */
function collectJSDocDiffs(oldApi, newApi, diffReporter) {
  JSDocDiffer.collectJSDocDiffs(oldApi, newApi, diffReporter);
}

/**
 * 比对两个SDK目录。
 * 
 * @param {string} oldDir 旧SDK目录
 * @param {string} newDir 新SDK目录
 * @param {string} oldVersion 旧SDK版本号
 * @param {string} newVersion 新SDK版本号
 * @returns {Map}
 */
async function compareSdks(oldDir, newDir) {
  const oldFiles = listApiDeclarationFiles(oldDir);
  const newFiles = listApiDeclarationFiles(newDir);
  const diffApis = getApiDiffs(newFiles, oldFiles, oldDir, newDir);
  return diffApis;
}

exports.ApiDiffer = {
  compareSdks: compareSdks,
};