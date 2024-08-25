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
const path = require("path");
let vscode = null;
try {
    vscode = require('vscode');
}
catch (err) {
    vscode = null;
}

class NapiLog {
    constructor() {
    }
}
NapiLog.LEV_NONE = 0;
NapiLog.LEV_ERROR = 1;
NapiLog.LEV_DEBUG = 2;
NapiLog.LEV_INFO = 3;

const LEV_STR = ["[NON]", "[ERR]", "[DBG]", "[INF]"]
var logLevel = NapiLog.LEV_ERROR;
var logFileName = null;
var logResultMessage = [true, ""]

function getDateString() {
    let nowDate = new Date();
    return nowDate.toLocaleString();
}

function saveLog(dateStr, levStr, detail) {
    if (logFileName) {
        let logStr = dateStr + " " + levStr + " " + detail + "\n";
        fs.appendFileSync(logFileName, logStr);
    }
}

NapiLog.init = function (level, fileName) {
    logLevel = level in [NapiLog.LEV_NONE, NapiLog.LEV_ERROR, NapiLog.LEV_DEBUG, NapiLog.LEV_INFO]
        ? level : NapiLog.LEV_ERROR;
    logFileName = fileName ? fileName : "napi_generator.log";
}

function getCallPath() {
    let callPath = ""
    let stackArray = new Error().stack.split('\n');
    for (let i = stackArray.length -1; i >=0 ; --i) {
        if (stackArray[i].indexOf("NapiLog.log") > 0 || stackArray[i].indexOf("Function.log") > 0) {
            let stackMsg = stackArray[i+1].trim()
            let leftIndex = stackMsg.indexOf("(")
            let rightIndex = stackMsg.indexOf(")")

            if (leftIndex > 0 && rightIndex > 0) {
                let funInfo = stackMsg.substring(0, leftIndex);
                let srcPath = stackMsg.substring(leftIndex + 1, rightIndex)
                let colNumIndex = srcPath.lastIndexOf(":")
                let colNum = srcPath.substring(colNumIndex + 1, srcPath.length)
                let lineNumIndex = srcPath.lastIndexOf(":", colNumIndex - 1)
                let lineNum = srcPath.substring(lineNumIndex + 1, colNumIndex)
                let filePath = srcPath.substring(0, lineNumIndex)

                callPath = "%s[%s(%s:%s)]".format(funInfo,filePath,lineNum,colNum)
            }
            break;
        }
    }

    return callPath;
}

function print(...args) {
    if (vscode) {
        vscode.window.showInformationMessage(...args);
    }
    console.log(args + "");
}

function recordLog(lev, ...args) {
    let origMsgInfo = args;
    let callPath = getCallPath();
    let dataStr = getDateString();
    let detail = args.join(" ");
    saveLog(dataStr  + " " + callPath, LEV_STR[lev], detail);
    if (lev == NapiLog.LEV_ERROR) {
        logResultMessage = [false, detail];
    }
    let logStr = callPath + " " + detail;
    if (logLevel <= lev) return logStr;
    NapiLog.logInfo(origMsgInfo[0]);
    return logStr;
}

NapiLog.logError = function (...args) {
    let logInfo = recordLog(NapiLog.LEV_ERROR, args);
    print(logInfo);
}

NapiLog.logDebug = function (...args) {
    recordLog(NapiLog.LEV_DEBUG, args);
}

NapiLog.logInfo = function (...args) {
    recordLog(NapiLog.LEV_INFO, args);
}

NapiLog.getResult = function () {
    return logResultMessage;
}

module.exports = {
    NapiLog
}