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
const {
  requireTypescriptModule, tagsArrayOfOrder, commentNodeWhiteList, parseJsDoc, ErrorType, ErrorLevel, FileType,
  inheritArr, ErrorValueInfo, createErrorInfo, isAscending } = require('../utils');
const { addAPICheckErrorLogs } = require('../compile_info');
const rules = require('../../code_style_rule.json');
const whiteLists = require('../../config/jsdocCheckWhiteList.json');
const ts = requireTypescriptModule();

/**
 * 判断标签是否为官方标签
 */
function isOfficialTag(tagName) {
  return tagsArrayOfOrder.indexOf(tagName) === -1;
}

/**
 * 对form标签的顺序做兼容处理
 */
function formOrderCheck(tags, tagIndex, firstIndex, secondIndex) {
  const frontFirstIndex = tagIndex - 1 > -1 ? tagsArrayOfOrder.indexOf(tags[tagIndex - 1].tag) : 0;
  const formNeighborArr = [frontFirstIndex, firstIndex];
  const newTagIndex = tagsArrayOfOrder.lastIndexOf(tags[tagIndex].tag);
  const newFormNeighborArr = [frontFirstIndex, newTagIndex];
  if (secondIndex > -1) {
    formNeighborArr.push(secondIndex);
    newFormNeighborArr.push(secondIndex);
  }
  if (!isAscending(formNeighborArr) && !isAscending(newFormNeighborArr)) {
    return false;
  }
  return true;
}



/**
 * 判断标签排列是否为升序
 */
function isAscendingOrder(tags) {
  let checkResult = true;
  for (let tagIndex = 0; tagIndex < tags.length; tagIndex++) {
    if (tagIndex + 1 < tags.length) {
      // 获取前后两个tag下标
      const firstIndex = tagsArrayOfOrder.indexOf(tags[tagIndex].tag);
      const secondIndex = tagsArrayOfOrder.indexOf(tags[tagIndex + 1].tag);
      // 判断标签是否为官方标签
      const firstTag = isOfficialTag(tags[tagIndex].tag);
      // 非自定义标签在前或数组降序时报错
      if (tags[tagIndex].tag !== 'form' && tags[tagIndex + 1].tag !== 'form' &&
        ((firstTag && secondIndex > -1) || (firstIndex > secondIndex && secondIndex > -1))) {
        checkResult = false;
        break;
      } else if (tags[tagIndex].tag === 'form') {
        checkResult = formOrderCheck(tags, tagIndex, firstIndex, secondIndex);
      }
    }
  };
  return checkResult;
}

// check jsdoc order
function checkApiOrder(comments) {
  const checkOrderRusult = [];
  comments.forEach(docInfo => {
    if (isAscendingOrder(docInfo.tags)) {
      checkOrderRusult.push({
        checkResult: true,
        errorInfo: '',
      });
    } else {
      const errorInfo = ErrorValueInfo.ERROR_ORDER;
      checkOrderRusult.push({
        checkResult: false,
        errorInfo: errorInfo,
      });
    }
  });
  return checkOrderRusult;
}
exports.checkApiOrder = checkApiOrder;

function checkAPITagName(tag, node, sourcefile, fileName, JSDocIndec) {
  const APITagNameResult = {
    checkResult: true,
    errorInfo: '',
  };
  const tagName = tag.tag;
  const docTags = [...rules.decorators.customDoc, ...rules.decorators.jsDoc];
  const decoratorRuleSet = new Set(docTags);
  if (!decoratorRuleSet.has(tagName) && commentNodeWhiteList.includes(node.kind)) {
    APITagNameResult.checkResult = false;
    APITagNameResult.errorInfo = createErrorInfo(ErrorValueInfo.ERROR_LABELNAME, [tagName]);
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.WRONG_SCENE, APITagNameResult.errorInfo,
      FileType.JSDOC, ErrorLevel.MIDDLE);
  }
  return APITagNameResult;
}
exports.checkAPITagName = checkAPITagName;

function checkParentInheritTag(node, inheritTag, inheritResult, JSocIndex) {
  const parentTagArr = [];
  if (ts.isSourceFile(node.parent)) {
    return inheritResult;
  }
  if (!ts.isModuleBlock(node.parent)) {
    const comments = parseJsDoc(node.parent);
    if (comments.length > 0 && Array.isArray(comments[comments.length - 1].tags)) {
      comments[comments.length - 1].tags.forEach(tag => {
        parentTagArr.push(tag.tag);
      });
      if (parentTagArr.includes(inheritTag)) {
        inheritResult.checkResult = false;
        inheritResult.errorInfo += createErrorInfo(ErrorValueInfo.ERROR_INFO_INHERIT, [inheritTag]);
      } else {
        checkParentInheritTag(node.parent, inheritTag, inheritResult, JSocIndex);
      }
    }
  } else if (ts.isModuleBlock(node.parent)) {
    checkParentInheritTag(node.parent, inheritTag, inheritResult, JSocIndex);
  }

  return inheritResult;
}

function checkInheritTag(comment, node, sourcefile, fileName, JSocIndex) {
  const inheritResult = {
    checkResult: true,
    errorInfo: '',
  };
  const tagArr = [];
  if (commentNodeWhiteList.includes(node.kind)) {
    comment.tags.forEach(tag => {
      tagArr.push(tag.tag);
    });
    inheritArr.forEach((inheritTag, index) => {
      if (!tagArr.includes(inheritTag)) {
        checkParentInheritTag(node, inheritArr[index], inheritResult, JSocIndex);
      }
    });
    if (!inheritResult.checkResult) {
      addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.WRONG_SCENE, inheritResult.errorInfo, FileType.API,
        ErrorLevel.MIDDLE);
    }
  }
  return inheritResult;
}
exports.checkInheritTag = checkInheritTag;
