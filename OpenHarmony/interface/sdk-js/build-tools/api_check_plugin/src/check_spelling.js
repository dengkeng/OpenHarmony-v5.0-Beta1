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

const fs = require('fs');
const path = require('path');
const { hasAPINote, getAPINote, overwriteIndexOf, ErrorType, ErrorLevel, FileType, requireTypescriptModule } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');
const rules = require('../code_style_rule.json');
const dictionariesContent = fs.readFileSync(path.resolve(__dirname, '../plugin/dictionaries.txt'), 'utf-8');
const dictionariesArr = dictionariesContent.split(/[(\r\n)\r\n]+/g);
const dictionariesSupplementaryContent = fs.readFileSync(path.resolve(__dirname,
  '../plugin/dictionaries_supplementary.txt'), 'utf-8');
const dictionariesSupplementaryArr = dictionariesSupplementaryContent.split(/[(\r\n)\r\n]+/g);
const dictionariesSet = new Set([...dictionariesArr, ...dictionariesSupplementaryArr, ...rules.decorators.customDoc,
  ...rules.decorators.jsDoc]);
const ts = requireTypescriptModule();

function checkSpelling(node, sourcefile, fileName) {
  if (ts.isIdentifier(node) && node.escapedText) {
    checkWordSpelling(node.escapedText.toString(), node, sourcefile, fileName, FileType.API);
  } else if (hasAPINote(node)) {
    const apiNote = getAPINote(node);
    const words = splitParagraph(apiNote);
    words.forEach(word => {
      checkWordSpelling(word, node, sourcefile, fileName, FileType.JSDOC);
    });
  }
}
exports.checkSpelling = checkSpelling;

function checkWordSpelling(nodeText, node, sourcefile, fileName, type) {
  const basicWords = splitComplexWords(nodeText);
  const errorWords = [];
  const suggest = [];
  basicWords.forEach(word => {
    if (!checkBaseWord(word.toLowerCase())) {
      errorWords.push(word);
    }
  });
  if (errorWords.length !== 0) {
    errorWords.forEach(errorWord => {
      const levArr = [];
      for (let i = 0; i < dictionariesArr.length; i++) {
        const dictionary = dictionariesArr[i];
        levArr.push(getLevenshteinValue(errorWord, dictionary));
      }
      const minLev = Math.min(...levArr);
      const indexArr = overwriteIndexOf(minLev, levArr);
      const MAX_LENGTH = 5;
      for (let i = 0; i < indexArr.length; i++) {
        if (i === MAX_LENGTH) {
          break;
        }
        suggest.push(dictionariesArr[indexArr[i]]);
      }
    });
    const errorInfo = `Error words in [${nodeText}]: {${errorWords}}.Do you want to spell it as [${suggest}]?`;
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.MISSPELL_WORDS, errorInfo, type, ErrorLevel.MIDDLE);
  }
}

/**
 *  check base word
 * @param {string} word
 * @return true or false
**/
function checkBaseWord(word) {
  if (/^[a-z][0-9]+$/g.test(word)) {
    return false;
  } else if (/^[A-Za-z]+/g.test(word) && !dictionariesSet.has(word.toLowerCase())) {
    return false;
  }
  return true;
}

function splitComplexWords(complexWord) {
  let basicWords = [];
  // splite underlineWord
  if (hasUnderline(complexWord)) {
    basicWords = complexWord.split(/(?<!^)\_/g);
  } else {
    // splite complexWord
    if (!/(?<!^)(?=[A-Z])/g.test(complexWord)) {
      basicWords.push(complexWord);
    } else {
      basicWords = complexWord.split(/(?<!^)(?=[A-Z])/g);
    }
  }
  const newBaseWords = [];
  basicWords.forEach(word => {
    if (/[0-9]/g.test(word)) {
      newBaseWords.concat(word.split(/0-9/g));
    } else {
      newBaseWords.push(word);
    };
  });
  return newBaseWords;
}
exports.splitComplexWords = splitComplexWords;

function hasUnderline(word) {
  return /(?<!^)\_/g.test(word);
}
exports.hasUnderline = hasUnderline;

function splitParagraph(paragraph) {
  const splitParagraphRegex = /[^\w]/g;
  const words = paragraph.split(splitParagraphRegex);
  return words;
}
exports.splitParagraph = splitParagraph;

// Levenshtein method
function getLevenshteinValue(word1, word2) {
  const word1Len = word1.length;
  const word2Len = word2.length;

  if (word1Len * word2Len === 0) {
    return Math.max(word1Len, word2Len);
  }
  // create Levenshtein two-dimensional array
  const levArr = Array.from(new Array(word1Len + 1), () => new Array(word2Len + 1));
  // set value 0 to Levenshtein two-dimensional array
  for (let i = 0; i < word1Len + 1; i++) {
    for (let j = 0; j < word2Len + 1; j++) {
      levArr[i][j] = 0;
    }
  }

  // init Levenshtein two-dimensional array
  for (let i = 0; i < word1Len + 1; i++) {
    levArr[i][0] = i;
  }
  for (let j = 0; j < word2Len + 1; j++) {
    levArr[0][j] = j;
  }

  // calculate levinstein distance
  for (let i = 1; i < word1Len + 1; i++) {
    for (let j = 1; j < word2Len + 1; j++) {
      const countByInsert = levArr[i][j - 1] + 1;
      const countByDel = levArr[i - 1][j] + 1;
      const countByReplace = word1.charAt(i - 1) === word2.charAt(j - 1) ?
        levArr[i - 1][j - 1] : levArr[i - 1][j - 1] + 1;
      levArr[i][j] = Math.min(countByInsert, countByDel, countByReplace);
    }
  }

  return levArr[word1Len][word2Len];
}
exports.getLevenshteinValue = getLevenshteinValue;
