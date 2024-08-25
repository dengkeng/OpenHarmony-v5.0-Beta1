/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
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
let vscode = null;
try {
    vscode = require('vscode');
}
catch (err) {
    vscode = null;
}

function utf8ArrayToStr(array) {
    var res, i, length, ch;
    var ch2, ch3;
  
    res = "";
    length = array.length;
    i = 0;
    while (i < length) {
      ch = array[i++];
      let c = ch >> 4;
      switch (c) {
        // 0xxxxxxx
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
          res += String.fromCharCode(ch);
          break;
        // 110x xxxx   10xx xxxx
        case 12: case 13:
          ({ ch2, i, res } = funcCase13(ch2, array, i, ch, res));
          break;
        // 1110 xxxx  10xx xxxx  10xx xxxx
        case 14:
          ({ ch2, i, ch3, res } = funcCase14(ch2, array, i, ch3, ch, res));
          break;
      }
    }
  
    return res;
  }
  
  function funcCase14(ch2, array, i, ch3, ch, res) {
    ch2 = array[i++];
    ch3 = array[i++];
    let tmp3 = (ch & 0x0F) << 12;
    let tmp4 = (ch2 & 0x3F) << 6;
    let tmp5 = (ch3 & 0x3F) << 0;
    res += String.fromCharCode(tmp3 | tmp4 | tmp5);
    return { ch2, i, ch3, res };
  }

  function funcCase13(ch2, array, i, ch, res) {
    ch2 = array[i++];
    let tmp = (ch & 0x1F) << 6;
    let tmp2 = ch2 & 0x3F;
    res += String.fromCharCode(tmp | tmp2);
    return { ch2, i, res };
  }

  function readFile(fn) {
    if (!fs.existsSync(fn)) {
      return "";
    }
    let data = fs.readFileSync(fn);
    data = utf8ArrayToStr(data);
    return data;
  }

module.exports = {
    readFile
}