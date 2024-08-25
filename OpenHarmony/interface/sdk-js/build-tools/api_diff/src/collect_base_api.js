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

const fs = require('fs');
const ts = require('typescript');
// 是否统计type类型API的开关，true表示合并
const typeCollection = true;
// 是否合并同名函数的开关，true不合并
const isNotMerge = true;
// 是否支持API Diff工具的开关，true表示支持
const supportDiffTool = true;

// 解析文件 文本内容并将结果push到列表中并去重
function parse(fileContentList) {
  const api = [];
  const exportApi = [];
  const returnDeclarationArr = new Set([]);
  const hash = new Set([]);

  fileContentList.forEach(item => {
    const fileName = item.fileName.replace(/\.d.ts$/g, '.ts');
    let packageName = item.fileRoot.indexOf('component\\ets\\') >= 0 ||
			item.fileRoot.indexOf('component/ets/') >= 0 ? 'ArkUI' : fileName.replace((/\@|.ts$/g), '').replace(/D:\\/g, '');
    ts.transpileModule(item.fileContent, {
      compilerOptions: {
        'target': ts.ScriptTarget.ES2017,
      },
      fileName: fileName,
      transformers: { before: [getReturnDeclarationArr(packageName, exportApi, returnDeclarationArr)] },
    });
  });

  fileContentList.forEach(item => {
    const fileName = item.fileName.replace(/\.d.ts$/g, '.ts');
    let packageName = item.fileRoot.indexOf('component\\ets\\') >= 0 ||
			item.fileRoot.indexOf('component/ets/') >= 0 ? 'ArkUI' : fileName.replace(/\@|.ts$/g, '').replace(/D:\\/g, '');
    ts.transpileModule(item.fileContent, {
      compilerOptions: {
        'target': ts.ScriptTarget.ES2017,
      },
      fileName: fileName,
      transformers: { before: [processDeclarationSourceFile(packageName, api, exportApi, returnDeclarationArr, hash, item.fileRoot)] },
    });
  });
  return api;
}

// 获取返回值类型
function visitAllNode(node, returnDeclarationArr) {
  if ((ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node)) && node && node.type &&
		ts.isTypeReferenceNode(node.type)) {
    returnDeclarationArr.add(node.type.typeName.getText());
  }
  node.getChildren().forEach(item => {
    visitAllNode(item, returnDeclarationArr);
  });
}

// 获取导入Api的数组
function getExportApi(node, packageName, exportApi) {
  node.statements.forEach(stat => {
    if (ts.isModuleDeclaration(stat)) {
      if (stat.getText().indexOf('namespace') > 0) {
        let apiInfo = {
          isSystemApi: '公开API',
          version: '',
          deprecated: '',
          permission: 'N/A',
          sysCap: 'N/A',
          model: '',
        };
        exportApi.push({
          packageName: packageName,
          className: stat.name.escapedText.toString(),
          methodName: '',
          apiInfo: getApiInfo(stat, apiInfo),
        });
      }
    }
  });
}

// 获取返回值类型和命名空间
const getReturnDeclarationArr = (packageName, exportApi, returnDeclarationArr) => {
  return (context) => {
    return (node) => {
      visitAllNode(node, returnDeclarationArr);
      getExportApi(node, packageName, exportApi);
      return node;
    };
  };
};


// 搜集API接口并去重
function processDeclarationSourceFile(packageName, api, exportApi, returnDeclarationArr, hash, dtsPath) {
  return (context) => {
    return (node) => {
      const statements = node.statements;
      const currentClassFuncSet = new Set([]);
      const currentTypeList = new Array();
      statements.forEach(stat => {
        if (ts.isTypeAliasDeclaration(stat)) {
          if (stat.type.types) {
            let typeObj = {
              name: stat.name.escapedText,
              value: [],
            };
            stat.type.types.forEach(type => {
              if (type.literal && type.literal.text) {
                typeObj.value.push(type.literal.text);
              }
            });
            if (typeObj.value.length > 0) {
              currentTypeList.push(typeObj);
            }
          }
        }
      });

      statements.forEach(stat => {
        let apiInfo = {
          isSystemApi: '公开API',
          version: '',
          deprecated: '',
          permission: 'N/A',
          sysCap: 'N/A',
          model: '',
          headimport: 'N/A',
          endexport: 'N/A',
        };
        collectApi(packageName, api, stat, apiInfo, exportApi, returnDeclarationArr, hash, dtsPath,
          currentTypeList, currentClassFuncSet);
      });
      return node;
    };
  };
}

function collectApi(packageName, api, stat, apiInfo, exportApi, returnDeclarationArr, hash, dtsPath, currentTypeList,
  currentClassFuncSet) {
  if (ts.isInterfaceDeclaration(stat)) {
    collectInterfaceDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo,
      currentTypeList, dtsPath);

  } else if (ts.isModuleDeclaration(stat)) {
    collectModuleDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo,
      currentTypeList, dtsPath);

  } else if (ts.isClassDeclaration(stat)) {
    collectClassDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo,
      currentTypeList, dtsPath);

  } else if (ts.isEnumDeclaration(stat)) {
    collectEnumDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo,
      currentTypeList, dtsPath);

  } else if (ts.isTypeAliasDeclaration(stat)) {
    // 不统计
  } else if (ts.isVariableStatement(stat)) {
    const apiName = stat.declarationList.declarations[0].name.escapedText;
    addApi(packageName, 'global', apiName, stat.getText().trim(), getApiInfo(stat, apiInfo),
      'Decorator', api, hash, dtsPath, 8);
  } else {
    if (ts.isMethodDeclaration(stat) || ts.isMethodSignature(stat) || ts.isFunctionDeclaration(stat)) {
      var methodName = stat.name.escapedText ? stat.name.escapedText.toString() : stat.name.text.toString();
      let className = '';
      exportApi.forEach(item => {
        if (item.methodName === methodName && item.packageName === packageName) {
          className = item.className;
          if (item.apiInfo) {
            apiInfo = item.apiInfo;
          }
        }
      });
      addFunctionOnOffApi(packageName, className, methodName, getApiInfo(stat, apiInfo), 'Method', api,
        hash, currentClassFuncSet, stat, dtsPath);
    }
  }
}

function collectInterfaceDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo, currentTypeList, dtsPath) {
  const className = stat.name.escapedText.toString();
  const interfaceChildren = stat.members;
  let tmpApiInfo = getApiInfo(stat, apiInfo);
  // 如果用于API Diff工具，就将一个类也统计为一个API；
  if (supportDiffTool) {
    addApi(packageName, className, '', '', tmpApiInfo, 'InterfaceDeclaration', api, hash, dtsPath, '10');
  }
  collectEachChildNode(interfaceChildren, packageName, className, 'Field', api, exportApi, returnDeclarationArr, hash,
    tmpApiInfo, currentTypeList, dtsPath);
}

function collectClassDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo, currentTypeList, dtsPath) {
  const className = stat.name.escapedText.toString();
  const classChildren = stat.members;
  let tmpApiInfo = getApiInfo(stat, apiInfo);
  if (supportDiffTool) {
    addApi(packageName, className, '', '', tmpApiInfo, 'ClassDeclaration', api, hash, dtsPath, '12');
  }
  collectEachChildNode(classChildren, packageName, className, 'Field', api, exportApi, returnDeclarationArr, hash,
    tmpApiInfo, currentTypeList, dtsPath);
}

function collectEnumDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo, currentTypeList, dtsPath) {
  const className = stat.name.escapedText.toString();
  const enumChildren = stat.members;
  let tmpApiInfo = getApiInfo(stat, apiInfo);
  if (supportDiffTool) {
    addApi(packageName, className, '', '', tmpApiInfo, 'EnumDeclaration', api, hash, dtsPath, '13');
  }
  collectEachChildNode(enumChildren, packageName, className, 'Enum', api, exportApi, returnDeclarationArr, hash,
    tmpApiInfo, currentTypeList, dtsPath);
}

function collectModuleDeclaration(stat, packageName, api, exportApi, returnDeclarationArr, hash, apiInfo, currentTypeList, dtsPath) {
  const className = stat.name.escapedText ? stat.name.escapedText.toString() : stat.name.text.toString();
  const moduleChildren = stat.body.statements;
  let tmpApiInfo = getApiInfo(stat, apiInfo);
  if (supportDiffTool) {
    addApi(packageName, className, '', '', tmpApiInfo, 'ModelDeclaration', api, hash, dtsPath, '11');
  }
  collectEachChildNode(moduleChildren, packageName, className, 'Field', api, exportApi, returnDeclarationArr, hash,
    tmpApiInfo, currentTypeList, dtsPath);
}

function collectTypeApi(child, packageName, className, faterApiType, api, exportApi, returnDeclarationArr,
  hash, apiInfo, dtsPath) {
  let typeObj = {
    name: child.name.escapedText,
    value: [],
  };
  if (child.type.types) {
    child.type.types?.forEach(type => {
      if (type.literal && type.literal.text) {
        typeObj.value.push(type.literal.text);
        if (typeCollection && type.literal) {
          let faterApiInfo = JSON.parse(JSON.stringify(apiInfo));
          addApi(packageName, child.name.escapedText, type.literal.text, child.getText(),
            getApiInfo(child, faterApiInfo), 'Type', api, hash, dtsPath, 1);
        }
      } else {
        if (type.getText() !== '') {
          typeObj.value.push(type.getText());
          if (typeCollection && type.literal) {
            let faterApiInfo = JSON.parse(JSON.stringify(apiInfo));
            addApi(packageName, child.name.escapedText, type.getText(), child.getText(),
              getApiInfo(child, faterApiInfo), 'Type', api, hash, dtsPath, 2);
          }
        }
      }
    });
  } else if (child.type.members) {
    child.type.members?.forEach(member => {
      member.type.types?.forEach(type => {
        if (type.literal && type.literal.text) {
          typeObj.value.push(type.literal.text);
          if (typeCollection) {
            let faterApiInfo = JSON.parse(JSON.stringify(apiInfo));
            addApi(packageName, child.name.escapedText, type.literal.text, child.getText(),
              getApiInfo(child, faterApiInfo), 'Type', api, hash, dtsPath, 3);
          }
        } else {
          if (type.getText() !== '') {
            typeObj.value.push(type.getText());
            if (typeCollection) {
              let faterApiInfo = JSON.parse(JSON.stringify(apiInfo));
              addApi(packageName, className, child.name.escapedText, child.getText(),
                getApiInfo(child, faterApiInfo), 'Type', api, hash, dtsPath, 4);
            }
          }
        }
      });
    });
  }
  return typeObj;
}

function collectEachChildNode(children, packageName, className, faterApiType, api, exportApi, returnDeclarationArr,
  hash, apiInfo, currentTypeList, dtsPath) {
  const currentClassFunSet = new Set([]);
  children.forEach(child => {
    if (ts.isTypeAliasDeclaration(child)) {
      if (child.type) {
        let typeObj = collectTypeApi(child, packageName, className, faterApiType, api, exportApi, returnDeclarationArr,
          hash, apiInfo, dtsPath);
        if (typeObj.value.length > 0) {
          currentTypeList.push(typeObj);
        }
      }
    }
  });
  children.forEach(child => {
    let faterApiInfo = JSON.parse(JSON.stringify(apiInfo));
    let apiType = new String(faterApiType);
    if (/export.*\{.*\}/g.test(child.getText())) {
      exportApi.push({
        packageName: packageName,
        className: className,
        methodName: child.getText().replace('export', '').replace('{', '').replace('}', '').replace(';', '').trim(),
        apiInfo: faterApiInfo,
      });
      return;
    }
    if (ts.isInterfaceDeclaration(child)) {
      collectInterfaceDeclaration(child, packageName, api, exportApi, returnDeclarationArr, hash, faterApiInfo, currentTypeList, dtsPath);
    } else if (ts.isModuleDeclaration(child)) {
      collectModuleDeclaration(child, packageName, api, exportApi, returnDeclarationArr, hash, faterApiInfo, currentTypeList, dtsPath);
    } else if (ts.isClassDeclaration(child)) {
      collectClassDeclaration(child, packageName, api, exportApi, returnDeclarationArr, hash, faterApiInfo, currentTypeList, dtsPath);
    } else if (ts.isEnumDeclaration(child)) {
      collectEnumDeclaration(child, packageName, api, exportApi, returnDeclarationArr, hash, faterApiInfo, currentTypeList, dtsPath);
    } else if (ts.isTypeAliasDeclaration(child)) {
      // 不统计
    } else {
      if ((ts.isMethodDeclaration(child) || ts.isMethodSignature(child) || ts.isFunctionDeclaration(child)) &&
				(child.name.escapedText === 'on' || child.name.escapedText === 'off') && child.parameters && child.parameters.length > 0) {
        apiType = 'Method';
        collectOnOffApi(child, apiType, packageName, className, faterApiType, api, exportApi, currentTypeList,
          hash, apiInfo, currentClassFunSet, dtsPath);
      } else {
        collectOtherApi(child, packageName, className, faterApiInfo, apiType, api,
          hash, currentClassFunSet, child, dtsPath, returnDeclarationArr);
      }
    }
  });
}

function collectOtherApi(child, packageName, className, faterApiInfo, apiType, api,
  hash, currentClassFunSet, child, dtsPath, returnDeclarationArr) {
  let methodName = '';
  if (ts.isMethodDeclaration(child) || ts.isMethodSignature(child) || ts.isFunctionDeclaration(child) ||
		ts.isCallSignatureDeclaration(child) || ts.isConstructSignatureDeclaration(child) ||
		ts.isIndexSignatureDeclaration(child)) {
    if (child.name) {
      methodName = child.name.getText();
    } else {
      methodName = className;
    }
    apiType = 'Method';
  } else if (ts.isPropertyDeclaration(child) || ts.isPropertySignature(child)) {
    if (child.type && child.type.parameters) {
      methodName = child.name.escapedText;
      apiType = 'Method';
    } else {
      methodName = child.name.escapedText;
      apiType = 'Field';
    }
  } else {
    if (child.name) {
      methodName = child.name.getText();
    }
  }
  if (methodName !== '') {
    addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
      hash, currentClassFunSet, child, dtsPath);
  } else {
    if (child.getText().indexOf('constructor') === 0) {
      methodName = 'constructor';
      apiType = 'Method';
    } else if (child.getText().indexOf('const') === 0) {
      methodName = collectFieleOrConstant(apiType, methodName, child, returnDeclarationArr).methodName;
      apiType = collectFieleOrConstant(apiType, methodName, child, returnDeclarationArr).apiType;
    } else if (/\w+:\s*\w+/g.test(child.getText())) {
      apiType = 'Field';
      methodName = child.getText().split(':')[0].trim();
    }
    if (methodName !== '') {
      addApi(packageName, className, methodName, child.getText(),
        getApiInfo(child, faterApiInfo), apiType, api, hash, dtsPath, 5);
    }
  }
}

function collectFieleOrConstant(apiType, methodName, child, returnDeclarationArr) {
  if (child.getText().replace('const', '').indexOf(':') > 0) {
    if (returnDeclarationArr.has(child.getText().replace('const', '').split(':')[1].trim())) {
      apiType = 'Field';
    } else {
      apiType = 'Constant';
    }
    methodName = child.getText().replace('const', '').split(':')[0].trim();
  } else if (child.getText().replace('const', '').indexOf('=') > 0) {
    if (returnDeclarationArr.has(child.getText().replace('const', '').split('=')[1].trim())) {
      apiType = 'Field';
    } else {
      apiType = 'Constant';
    }
    methodName = child.getText().replace('const', '').split('=')[0].trim();
  }
  return { apiType, methodName };
}

function collectOnOffApi(child, apiType, packageName, className, faterApiInfo, api, exportApi, currentTypeList,
  hash, apiInfo, currentClassFunSet, dtsPath) {
  for (let i = 0; i < child.parameters.length; i++) {
    const param = child.parameters[i];
    if (param.name.escapedText === 'type' || param.name.escapedText === 'event' ||
			param.name.escapedText === 'eventType') {
      if (param.type && param.type.literal && param.type.literal.text) {
        collectTypeOrEventApi(packageName, className, faterApiInfo, apiType, api,
          hash, currentClassFunSet, child, dtsPath, param);
      } else if (param.type && param.type.types && param.type.types.length > 0) {
        param.type.types.forEach(type => {
          if (type.literal && type.literal.text) {
            let methodName = child.name.escapedText + '_' + type.literal.text;
            addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
              hash, currentClassFunSet, child, dtsPath);
          }
        });
      } else if (param.type && param.type.typeName && param.type.typeName.escapedText) {
        inCurrentTypeListApi(packageName, className, faterApiInfo, apiType, api,
          hash, currentClassFunSet, child, dtsPath, currentTypeList, param);
      } else if (param.type && param.type.typeName && param.type.typeName.left &&
				param.type.typeName.right) {
        let methodName = child.name.escapedText + '_' + param.type.typeName.left.escapedText + '_' +
					param.type.typeName.right.escapedText;
        addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
          hash, currentClassFunSet, child, dtsPath);
      } else {
        let methodName = child.name.escapedText;
        addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
          hash, currentClassFunSet, child, dtsPath);
      }
      break;
    } else {
      let methodName = child.name.escapedText;
      addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
        hash, currentClassFunSet, child, dtsPath);
    }
  }
}

function inCurrentTypeListApi(packageName, className, faterApiInfo, apiType, api, hash, currentClassFunSet, child,
  dtsPath, currentTypeList, param) {
  if (currentTypeList && currentTypeList.length > 0) {
    currentTypeList.forEach(type => {
      if (type.name === param.type.typeName.escapedText) {
        type.value.forEach(typeString => {
          let methodName = child.name.escapedText + '_' + typeString;
          addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
            hash, currentClassFunSet, child, dtsPath);
        });
      }
    });
  } else {
    let methodName = child.name.escapedText;
    addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
      hash, currentClassFunSet, child, dtsPath);
  }
}

function collectTypeOrEventApi(packageName, className, faterApiInfo, apiType, api,
  hash, currentClassFunSet, child, dtsPath, param) {
  const typeTextArr = param.getText().replace(/\s*/g, '').split(':');
  if (typeTextArr[0] === 'type' || typeTextArr[0] === 'event') {
    let methodName = child.name.escapedText + '_' + param.type.literal.text;
    addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
      hash, currentClassFunSet, child, dtsPath);
  } else {
    let methodName = child.name.escapedText + '_' + param.type.literal.text;
    addFunctionOnOffApi(packageName, className, methodName, faterApiInfo, apiType, api,
      hash, currentClassFunSet, child, dtsPath);
  }
}

function addFunctionOnOffApi(packageName, className, methodName, apiInfo, apiType, api,
  hash, currentClassFunSet, childNode, dtsPath) {
  // 合并同名函数
  if (currentClassFunSet.has(methodName) && !isNotMerge) {
    for (let i = 0; i < api.length; i++) {
      const curApi = api[i];
      if (curApi.packageName === packageName && curApi.className === className &&
				curApi.methodName === methodName) {
        if (curApi.methodText.indexOf(`${childNode.getText().replace('declare', '').trim()}`) < 0) {
          curApi.methodText += `\n${childNode.getText().replace('declare', '').replace(/\r|\n/ig, '').trim()}`;
          break;
        }
      }
    }
  } else {
    notMergeSameNameFun(packageName, className, methodName, apiInfo, apiType, api,
      hash, currentClassFunSet, childNode, dtsPath);
  }
}

function notMergeSameNameFun(packageName, className, methodName, apiInfo, apiType, api,
  hash, currentClassFunSet, childNode, dtsPath) {
  if (!currentClassFunSet.has(methodName)) {
    currentClassFunSet.add(methodName);
    addApi(packageName, className, methodName, childNode.getText().replace('declare', '').trim(),
      getApiInfo(childNode, apiInfo), apiType, api, hash, dtsPath, 6);
  } else {
    if (childNode.getFullText().indexOf('\/**') >= 0) {
      addApi(packageName, className, methodName, childNode.getText().replace('declare', '').trim(),
        getApiInfo(childNode, apiInfo), apiType, api, hash, dtsPath, 7);
    } else {
      let firstApiInfo = {};
      for (let i = 0; i < api.length; i++) {
        const curApi = api[i];
        if (curApi.packageName === packageName && curApi.className === className &&
					curApi.methodName === methodName) {
          firstApiInfo.isSystemApi = curApi.isSystemApi;
          firstApiInfo.version = curApi.version;
          firstApiInfo.sysCap = curApi.sysCap;
          firstApiInfo.permission = curApi.permission;
          firstApiInfo.model = curApi.model;
          firstApiInfo.deprecated = curApi.deprecated;
          firstApiInfo.useinsteadInfo = curApi.useinsteadInfo;
          firstApiInfo.typeInfo = curApi.typeInfo;
          firstApiInfo.errorCode = curApi.errorCode;
        }
      }
      addApi(packageName, className, methodName, childNode.getText().replace('declare', '').trim(),
        firstApiInfo, apiType, api, hash, dtsPath, 8);
    }
  }
}

function getApiInfo(node, apiInfos) {
  const notesStr = node.getFullText().replace(node.getText(), '');
  let noteArr = notesStr.split('/**');
  if (notesStr !== '' && noteArr.length <= 2) {
    const note = 'one';
    return getParentApiInfo(node, 'NA', note);
  } else if (notesStr !== '' && noteArr.length >= 3) {
    const note = 'two';
    const newNoteStr = noteArr[2];
    return getParentApiInfo(node, newNoteStr, note);
  } else if (notesStr === '') {
    const note = 'one';
    return getParentApiInfo(node, 'NA', note);
  }
}

function matchLabelInfo(node, noteParagraph, note) {
  const noteInfo = {};
  const notesStr = noteParagraph === 'NA' ? node.getFullText().replace(node.getText(), '') : noteParagraph;
  noteInfo.note = note;
  noteInfo.model = getModelInfo(notesStr);
  noteInfo.errorCode = getErrorCode(notesStr);
  noteInfo.deprecated = getDeprecatedInfo(notesStr);
  noteInfo.permission = getPermissionInfo(notesStr);
  if (/\@[S|s][Y|y][S|s][T|t][E|e][M|m][A|a][P|p][I|i]/g.test(notesStr)) {
    noteInfo.isSystemApi = '系统API';
  } else {
    noteInfo.isSystemApi = '公开API';
  }

  if (/\@[S|s][I|i][N|n][C|c][E|e]\s*(\d+)/g.test(notesStr)) {
    notesStr.replace(/\@[S|s][I|i][N|n][C|c][E|e]\s*(\d+)/g, (versionInfo) => {
      noteInfo.version = versionInfo.replace(/\@[S|s][I|i][N|n][C|c][E|e]/g, '').trim();
    });
  } else {
    noteInfo.version = 'N/A';
  }

  if (/\@[S|s][Y|y][S|s][C|c][A|a][P|p]\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(notesStr)) {
    notesStr.replace(/\@[S|s][Y|y][S|s][C|c][A|a][P|p]\s*((\w|\.|\/|\{|\@|\}|\s)+)/g, sysCapInfo => {
      noteInfo.sysCap = sysCapInfo.replace(/\@[S|s][Y|y][S|s][C|c][A|a][P|p]/g, '').trim();
    });
  }

  if (/\@[U|u][S|s][E|e][I|i][N|n][S|s][T|t][E|e][A|a][D|d]\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(notesStr)) {
    notesStr.replace(/\@[U|u][S|s][E|e][I|i][N|n][S|s][T|t][E|e][A|a][D|d]\s*((\w|\.|\/|\{|\@|\}|\s)+)/g, useinsteadInfo => {
      noteInfo.useinsteadInfo = useinsteadInfo.replace(/\@[U|u][S|s][E|e][I|i][N|n][S|s][T|t][E|e][A|a][D|d]\s*/g, '')
        .replace(/\r|\n/ig, '').replace('*/', '');
    });
  } else {
    noteInfo.useinsteadInfo = 'N/A';
  }

  if (/\@[T|t][Y|y][P|p][E|e]\s\{\s(\S)+\s\}/g.test(notesStr)) {
    notesStr.replace(/\@[T|t][Y|y][P|p][E|e]\s\{\s(\S)+\s\}/g, typeInfo => {
      noteInfo.typeInfo = typeInfo.replace(/\@[T|t][Y|y][P|p][E|e]\s/g, '').replace('{', '').replace('}', '').trim();
    });
  } else {
    noteInfo.typeInfo = 'N/A';
  }
  return noteInfo;
}

function getPermissionInfo(notesStr) {
  let permission = '';
  if (/\@[P|p][E|e][R|r][M|m][I|i][S|s][S|s][I|i][O|o][N|n]\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(notesStr)) {
    notesStr.replace(/\@[P|p][E|e][R|r][M|m][I|i][S|s][S|s][I|i][O|o][N|n]\s*((\w|\.|\/|\{|\@|\}|\s)+)/g,
      permissionInfo => {
        permission = permissionInfo.replace(
          /\@[P|p][E|e][R|r][M|m][I|i][S|s][S|s][I|i][O|o][N|n]/g, '').trim();
        return permission;
      });
  } else {
    permission = 'N/A';
  }
  return permission;
}

function getDeprecatedInfo(notesStr) {
  let deprecated = '';
  if (/\@[D|d][E|e][P|p][R|r][E|e][C|c][A|a][T|t][E|e][D|d].*[S|s][I|i][N|n][C|c][E|e]\s*(\d+)/g.test(notesStr)) {
    notesStr.replace(/\@[D|d][E|e][P|p][R|r][E|e][C|c][A|a][T|t][E|e][D|d].*[S|s][I|i][N|n][C|c][E|e]\s*(\d+)/g,
      deprecatedInfo => {
        deprecated = deprecatedInfo.replace(
          /\@[D|d][E|e][P|p][R|r][E|e][C|c][A|a][T|t][E|e][D|d].*[S|s][I|i][N|n][C|c][E|e]\s*/g, '').trim();
				
      });
  } else {
    deprecated = 'N/A';
  }
  return deprecated;
}

function getErrorCode(notesStr) {
  let errorCode = '';
  if (/\@throws (\{ BusinessError }|\{BusinessError})\s*(\d+)/g.test(notesStr)) {		
    notesStr.replace(/\@throws (\{ BusinessError }|\{BusinessError})\s*(\d+)/g, (code) => {
      if (errorCode === '') {
        errorCode += `${code.replace(/\@throws (\{ BusinessError }|\{BusinessError})/, '')}`;
      } else {
        errorCode += `,${code.replace(/\@throws (\{ BusinessError }|\{BusinessError})/, '')}`;
      }
    });
  } else {
    errorCode = 'N/A';
  }
  return errorCode;
}

function getModelInfo(notesStr) {
  let model = '';
  if (/\@[F|f][A|a][M|m][O|o][D|d][E|e][L|l][O|o][N|n][L|l][Y|y]/g.test(notesStr)) {
    notesStr.replace(/\@[F|f][A|a][M|m][O|o][D|d][E|e][L|l][O|o][N|n][L|l][Y|y]/g, modelInfo => {
      model = modelInfo;
    });
  } else if (/\@[S|s][T|t][A|a][G|g][E|e][M|m][O|o][D|d][E|e][L|l][O|o][N|n][L|l][Y|y]/g.test(notesStr)) {
    notesStr.replace(/\@[S|s][T|t][A|a][G|g][E|e][M|m][O|o][D|d][E|e][L|l][O|o][N|n][L|l][Y|y]/g, modelInfo => {
      model = modelInfo;
    });
  } else {
    model = 'N/A';
  }
  return model;
}

function getParentApiInfo(node, noteStr, note) {
  let apiInfo = {};
  if (!apiInfo.sysCap) {
    if (matchLabelInfo(node, noteStr, note).sysCap) {
      apiInfo.sysCap = matchLabelInfo(node, noteStr, note).sysCap;
    } else if (node.parent) {
      apiInfo.sysCap = getParentApiInfo(node.parent, noteStr, apiInfo).sysCap;
    } else {
      apiInfo.sysCap = 'N/A';
    }
  }
  if (!apiInfo.deprecated) {
    if (matchLabelInfo(node, noteStr, note).deprecated) {
      apiInfo.deprecated = matchLabelInfo(node, noteStr, note).deprecated;
    } else if (node.parent) {
      apiInfo.deprecated = getParentApiInfo(node.parent, noteStr, apiInfo).deprecated;
    } else {
      apiInfo.deprecated = 'N/A';
    }
  }
  apiInfo.typeInfo = matchLabelInfo(node, noteStr, note).typeInfo;
  apiInfo.useinsteadInfo = matchLabelInfo(node, noteStr, note).useinsteadInfo;
  apiInfo.errorCode = matchLabelInfo(node, noteStr, note).errorCode;
  apiInfo.note = matchLabelInfo(node, noteStr, note).note;
  apiInfo.version = matchLabelInfo(node, noteStr, note).version;
  apiInfo.model = matchLabelInfo(node, noteStr, note).model;
  apiInfo.isSystemApi = matchLabelInfo(node, noteStr, note).isSystemApi;
  apiInfo.permission = matchLabelInfo(node, noteStr, note).permission;
  return apiInfo;
}


// =======================================================================================
function addApiImport(packageName, headimport, api, dtsPath) {
  api.push({
    packageName: packageName,
    className: '',
    methodName: '',
    methodText: '',
    isSystemApi: '',
    version: '',
    deprecated: '',//废弃起始版本
    apiType: 'import',//apiType
    sysCap: '',
    permission: '',
    model: '',
    headimport: headimport,
    endexport: '',
    dtsPath: dtsPath,
  });
}

function addApiExport(packageName, endexport, api, dtsPath) {
  api.push({
    packageName: packageName,
    className: '',
    methodName: '',
    methodText: '',
    isSystemApi: '',
    version: '',
    deprecated: '',//废弃起始版本
    apiType: 'export',//apiType
    sysCap: '',
    permission: '',
    model: '',
    headimport: '',
    endexport: endexport,
    dtsPath: dtsPath,
  });
}

function addApi(packageName, className, methodName, methodText, apiInfo, apiType, api, hash, dtsPath, type) {
  let recard = isNotMerge ? `${packageName}.${className}/${methodName}/${methodText}` :
    `${packageName}.${className}/${methodName}`;
  if (!hash.has(recard)) {
    hash.add(recard);
    api.push({
      packageName: packageName,
      className: className,
      methodName: methodName,
      methodText: methodText.replace(/export\s/g, ''),
      isSystemApi: apiInfo.isSystemApi,
      version: apiInfo.version,
      deprecated: apiInfo.deprecated,//废弃起始版本
      apiType: apiType,
      sysCap: apiInfo.sysCap,
      permission: apiInfo.permission,
      model: apiInfo.model,
      headimport: '',
      endexport: '',
      dtsPath: dtsPath,
      useinsteadInfo: apiInfo.useinsteadInfo,
      errorCode: apiInfo.errorCode,
      typeInfo: apiInfo.typeInfo,
      note: apiInfo.note,
    });
  }
}
exports.parse = parse;