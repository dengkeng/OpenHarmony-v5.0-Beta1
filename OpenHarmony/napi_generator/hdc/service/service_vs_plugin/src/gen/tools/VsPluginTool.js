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
const os = require('os');
const tsc = require("../../node_modules/typescript");
const fs = require('fs');
let vscode = null;
try {
    vscode = require('vscode');
}
catch (err) {
    vscode = null;
}

function replaceAll(s, sfrom, sto) {
    while (s.indexOf(sfrom) >= 0) {
        s = s.replace(sfrom, sto)
    }
    return s;
}

function detectPlatform() {
	if (os.type() == 'Windows_NT') {
		return 'win';
	} else if (os.type() == 'Darwin') {
		return 'mac';
	} else if (os.type() == 'Linux') {
		return 'Linux';
	}
}

function checkFileError(ifname) {
    let program = tsc.createProgram([ifname], {})
    let emitResult = program.emit();
    let allDiagnostics = tsc.getPreEmitDiagnostics(program).concat(emitResult.diagnostics);

    let errorMsg = ''
    allDiagnostics.forEach(diagnostic => {
        if (diagnostic.file) {
            let { line, character } = tsc.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start);
            let message = tsc.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
            errorMsg += `${diagnostic.file.fileName} (${line + 1},${character + 1}): ${message}\n`;
        } else {
            errorMsg += tsc.flattenDiagnosticMessageText(diagnostic.messageText, "\n") + "\n";
        }
    });

    if (allDiagnostics.length > 0) {
        return [false, errorMsg];
    }
    return [true, ""];
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
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
          // 0xxxxxxx
          res += String.fromCharCode(ch);
          break;
        case 12: case 13:
          // 110x xxxx   10xx xxxx
          ch2 = array[i++];
          let tmp = (ch & 0x1F) << 6;
          let tmp2 = ch2 & 0x3F;
          res += String.fromCharCode(tmp | tmp2);
          break;
        case 14:
          // 1110 xxxx  10xx xxxx  10xx xxxx
          ch2 = array[i++];
          ch3 = array[i++];
          let tmp3 = (ch & 0x0F) << 12;
          let tmp4 = (ch2 & 0x3F) << 6;
          let tmp5 = (ch3 & 0x3F) << 0;
          res += String.fromCharCode(tmp3 | tmp4 | tmp5);
          break;
      }
    }
  
    return res;
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
    replaceAll,
    detectPlatform,
    checkFileError,
    readFile
}