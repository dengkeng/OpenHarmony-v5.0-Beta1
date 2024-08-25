/*
* Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
*
* http://www.apache.org/licenses/LICENSE-2.0 
*
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License. 
*/
const fs = require('fs');
const MOVE_EIGHTEEN = 18;
const MOVE_TWELVE = 12;
const MOVE_SIX = 6;

function utf8ArrayToStr(array) {
    let char2, char3;

    let outStr = "";
    let len = array.length;
    let i = 0;
    while (i < len) {
        let ch = array[i++];
        switch (ch >> 4) {
            case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
                // 0xxxxxxx
                outStr += String.fromCharCode(ch);
                break;
            case 12: case 13:
                // 110x xxxx   10xx xxxx
                char2 = array[i++];
                outStr += String.fromCharCode(((ch & 0x1F) << 6) | (char2 & 0x3F));
                break;
            case 14:
                // 1110 xxxx  10xx xxxx  10xx xxxx
                char2 = array[i++];
                char3 = array[i++];
                outStr += String.fromCharCode(((ch & 0x0F) << 12) |
                    ((char2 & 0x3F) << 6) |
                    ((char3 & 0x3F) << 0));
                break;
        }
    }

    return outStr;
}

function stringToUint8Array(string, option = { streamBool: false }) {
    if (option.streamBool) {
        throw new Error(`Failed to encode: the 'streamBool' option is unsupported.`);
    }
    const len = string.length;
    let position = 0;
    // output position
    let atPos = 0;
    // 1.5x size
    let tlength = Math.max(32, len + (len >> 1) + 7);
    // ... but atPos 8 byte offset
    let target = new Uint8Array((tlength >> 3) << 3);

    while (position < len) {
        let value = string.charCodeAt(position++);
        let isContinue = false;
        if (value >= 0xd800 && value <= 0xdbff) {
            if (position < len) {// high surrogate
                const extra = string.charCodeAt(position);
                if ((extra & 0xfc00) === 0xdc00) {
                    ++position;
                    value = ((value & 0x3ff) << 10) + (extra & 0x3ff) + 0x10000;
                }
            }
            if (value >= 0xd800 && value <= 0xdbff) {
                isContinue = true;  // drop lone surrogate
            }
        }

        if (!isContinue) {
            // expand the buffer if we couldn't write 4 bytes
            if (atPos + 4 > target.length) {
                tlength += 8;  // minimum extra
                tlength *= (1.0 + (position / string.length) * 2);  // take 2x the remaining
                tlength = (tlength >> 3) << 3;  // 8 byte offset

                target = uint8Array(tlength, target);
            }

            let calculateResult = calculate(value, target, atPos)
            isContinue = calculateResult[0]
            target = calculateResult[1]
            atPos = calculateResult[2]
        }
    }
    return target.slice(0, atPos);
}

function calculate(val, target, at) {
    let isContinue = false
    if ((val & 0xffffff80) === 0) {  // 1-byte
        target[at++] = val;  // ASCII
        isContinue = true;
    } else if ((val & 0xffe00000) === 0) {  // 4-byte
        target[at++] = ((val >> MOVE_EIGHTEEN) & 0x07) | 0xf0;
        target[at++] = ((val >> MOVE_TWELVE) & 0x3f) | 0x80;
        target[at++] = ((val >> MOVE_SIX) & 0x3f) | 0x80;
    } else if ((val & 0xffff0000) === 0) {  // 3-byte
        target[at++] = ((val >> MOVE_TWELVE) & 0x0f) | 0xe0;
        target[at++] = ((val >> MOVE_SIX) & 0x3f) | 0x80;
    } else if ((val & 0xfffff800) === 0) {  // 2-byte
        target[at++] = ((val >> MOVE_SIX) & 0x1f) | 0xc0;
    } else {
        isContinue = true;
    }
    if (!isContinue) {
        target[at++] = (val & 0x3f) | 0x80;
    }
    return [isContinue, target, at]
}

function uint8Array(tlen, target) {
    const update = new Uint8Array(tlen);
    update.set(target);
    return update
}

function readFile(fn) {
  if (!fs.existsSync(fn)) {
    return "";
  }
  let data = fs.readFileSync(fn);
  data = utf8ArrayToStr(data);
  return data;
}

function writeFile(fn, str) {
  fs.writeFileSync(fn, str, { encoding: 'utf8' });
}

function appendWriteFile(fn, str) {
    fs.appendFile(fn, str, 'utf8', err => {
        if (err) {
            console.error(err);
            return;
        }
    });
}

// 随机生成整数
function generateRandomInteger(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * 获取Json文件内容
 * @returns
 */
function getJsonCfg(jsonFilePath) {
    let jsonCfg = null; // json 配置文件
    let jsonFile = fs.readFileSync(jsonFilePath, { encoding: "utf8" });
    jsonCfg = JSON.parse(jsonFile);
    return jsonCfg;
}

module.exports = {
    readFile,
    writeFile,
    appendWriteFile,
    generateRandomInteger,
    getJsonCfg
}