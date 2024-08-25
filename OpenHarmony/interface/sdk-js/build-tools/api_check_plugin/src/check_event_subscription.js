/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

const { ErrorType, ErrorLevel, LogType, requireTypescriptModule, checkVersionNeedCheck, createErrorInfo, ErrorValueInfo } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');
const { checkSmallHump } = require('./check_hump');
const ts = requireTypescriptModule();

// check if on and off functions show in pair
function checkOnAndOffAppearInPair(node, sourcefile, fileName, onEventAllNames, onEventCheckNames, offEventAllNames, offEventCheckNames) {
  for (const value of onEventCheckNames) {
    if (!offEventAllNames.has(value)) {
      const checkErrorResult = createErrorInfo(ErrorValueInfo.ERROR_EVENT_ON_AND_OFF_PAIR, []);
      addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.API_PAIR_ERRORS, checkErrorResult, LogType.LOG_API,
        ErrorLevel.MIDDLE);
    }
  }
  for (const value of offEventCheckNames) {
    if (!onEventAllNames.has(value)) {
      const checkErrorResult = createErrorInfo(ErrorValueInfo.ERROR_EVENT_ON_AND_OFF_PAIR, []);
      addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.API_PAIR_ERRORS, checkErrorResult, LogType.LOG_API,
        ErrorLevel.MIDDLE);
    }
  }
}

function checkTheFirstParameter(node, sourcefile, fileName) {
  // check the version
  if (!checkVersionNeedCheck(node)) {
    return;
  }
  if (node.parameters && node.parameters.length > 0 && node.parameters[0].type) {
    const firstParameterType = node.parameters[0].type;
    // check the type of first parameter
    if ((firstParameterType.kind === ts.SyntaxKind.LiteralType && firstParameterType.literal.kind ===
      ts.SyntaxKind.StringLiteral)) {
      // if the first parameter is string
      const parameterName = firstParameterType.literal.text;
      if (!checkSmallHump(parameterName)) {
        const checkErrorResult = createErrorInfo(ErrorValueInfo.ERROR_EVENT_NAME_SMALL_HUMP, [parameterName]);
        addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.PARAMETER_ERRORS, checkErrorResult, LogType.LOG_API,
          ErrorLevel.MIDDLE);
        return;
      }
    } else if (firstParameterType.kind === ts.SyntaxKind.StringKeyword) {
      // if the first parameter is 'string'
      return;
    } else {
      let checkErrorResult = createErrorInfo(ErrorValueInfo.ERROR_EVENT_NAME_STRING, []);
      if (firstParameterType.typeName && firstParameterType.typeName.escapedText === '') {
        checkErrorResult = createErrorInfo(ErrorValueInfo.ERROR_EVENT_NAME_NULL, []);
      }
      addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.PARAMETER_ERRORS, checkErrorResult, LogType.LOG_API,
        ErrorLevel.MIDDLE);
    }
  }
}

function isBasicType(node) {
  if (node.type !== undefined) {
    const nodeKind = node.type.kind;
    const basicTypes = new Set([ts.SyntaxKind.NumberKeyword, ts.SyntaxKind.StringKeyword, ts.SyntaxKind.BooleanKeyword, ts.SyntaxKind.UndefinedKeyword,
      ts.SyntaxKind.LiteralType]);
    if (basicTypes.has(nodeKind)) {
      return true;
    }
  }
  return false;
}

// check if the callback parameter of off function is optional
function checkOffFunctions(nodes, sourcefile, fileName) {
  let isAllCallbackMandatory = true; 
  let someoneMissingCallback = false;
  let someoneHasCallback = false;
  for (let node of nodes) {
    if (node.parameters.length === 0) {
      continue;
    }
    const lastParameter = node.parameters[node.parameters.length - 1];
    if (isBasicType(lastParameter)) {
      someoneMissingCallback = true;
    } else {
      someoneHasCallback = true;
      if (lastParameter.questionToken !== undefined) {
        isAllCallbackMandatory = false;
      }
    }
  }
  // has off fucntion with callback parameter which is not optional, and doesn't have off function without callback parameter
  if (isAllCallbackMandatory && !someoneMissingCallback) {
    const checkErrorResult = createErrorInfo(ErrorValueInfo.ERROR_EVENT_CALLBACK_OPTIONAL, []);
    addAPICheckErrorLogs(nodes[0], sourcefile, fileName, ErrorType.PARAMETER_ERRORS, checkErrorResult, LogType.LOG_API,
      ErrorLevel.MIDDLE);
  }
}

function extendEventNames(node, allNames, checkNames) {
  const nodeType = node.parameters[0].type;
  let eventName = '';
  if (nodeType.kind === ts.SyntaxKind.LiteralType) {
    eventName = nodeType.literal.text;
    allNames.add(eventName);
  } else if (nodeType.kind === ts.SyntaxKind.StringKeyword) {
    eventName = 'string';
    allNames.add(eventName);
  }
  if (checkVersionNeedCheck(node) && eventName !== '') {
    checkNames.add(eventName);
  }
  return eventName;
}

function extendEventNodes(node, eventName, nodesSet) {
// store the off function node based on their names
  if (!nodesSet.get(eventName)) {
    nodesSet.set(eventName, [node]);
  } else {
    let curNodes = nodesSet.get(eventName);
    curNodes.push(node);
    nodesSet.set(eventName, curNodes);
  }
}

// handle event subscription node
function handleVariousEventSubscriptionAPI(childNode, childNodeName, sourcefile, fileName, onEventAllNames, onEventCheckNames,
  offEventAllNames, offEventCheckNames, offEventNodes) {
  if (childNode.parameters && childNode.parameters.length > 0 && childNode.parameters[0].type) {
    // judge the event subscription api type
    if (childNodeName === 'on') {
      extendEventNames(childNode, onEventAllNames, onEventCheckNames);
      checkTheFirstParameter(childNode, sourcefile, fileName, childNodeName);
    } else if (childNodeName === 'off') {
      let eventName = extendEventNames(childNode, offEventAllNames, offEventCheckNames);
      extendEventNodes(childNode, eventName, offEventNodes);
      checkTheFirstParameter(childNode, sourcefile, fileName, childNodeName);
    } else if (childNodeName === 'once' || childNodeName === 'emit') {
      checkTheFirstParameter(childNode, sourcefile, fileName, childNodeName);
    }
  }
}

function checkEventSubscription(node, sourcefile, fileName) {
  // if the node is namespace or interface
  if ((ts.isInterfaceDeclaration(node)) || ts.isModuleBlock(node) || ts.isModuleDeclaration(node) ||
    ts.isClassDeclaration(node) || node === sourcefile) {
    const onEventAllNames = new Set();
    const onEventCheckNames = new Set();
    const offEventAllNames = new Set();
    const offEventCheckNames = new Set();
    const offEventNodes = new Map();
    let childNodes = node.members;
    if (ts.isModuleDeclaration(node)) {
      childNodes = node.body.statements;
    }
    if (childNodes === undefined) {
      return;
    }
    childNodes.forEach((childNode) => {
      // if the node is method or function
      if (ts.isFunctionDeclaration(childNode) || ts.isMethodDeclaration(childNode) || ts.isMethodSignature(childNode)) {
        // if the version needed to be check
        let childNodeName = (childNode.name && ts.isIdentifier(childNode.name)) ?
          childNode.name.getText() :
          '';
        handleVariousEventSubscriptionAPI(childNode, childNodeName, sourcefile, fileName, onEventAllNames,
          onEventCheckNames, offEventAllNames, offEventCheckNames, offEventNodes);
      }
    });
    // check the callback parameter of off function is optional
    for (const event of offEventCheckNames) {
      checkOffFunctions(offEventNodes.get(event), sourcefile, fileName);
    }
    // check if the on and off functions of one event shows in pair
    checkOnAndOffAppearInPair(node, sourcefile, fileName, onEventAllNames, onEventCheckNames, offEventAllNames, offEventCheckNames);
  }
}
exports.checkEventSubscription = checkEventSubscription;
