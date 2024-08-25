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

class VsPluginLog {
    constructor() {
    }
}
VsPluginLog.LEV_NONE = 0;
VsPluginLog.LEV_ERROR = 1;
VsPluginLog.LEV_DEBUG = 2;
VsPluginLog.LEV_INFO = 3;

const LEV_STR = ["[NON]", "[ERR]", "[DBG]", "[INF]"]
var logLevel = VsPluginLog.LEV_ERROR;
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

VsPluginLog.init = function (level, fileName) {
    logLevel = level in [VsPluginLog.LEV_NONE, VsPluginLog.LEV_ERROR, VsPluginLog.LEV_DEBUG, VsPluginLog.LEV_INFO]
        ? level : VsPluginLog.LEV_ERROR;
    logFileName = fileName ? fileName : "napi_generator.log";
}

function recordLog(lev, ...args) {
    let dataStr = getDateString();
    let detail = args.join(" ");
    saveLog(dataStr, LEV_STR[lev], detail);
    if (lev == VsPluginLog.LEV_ERROR) {
        logResultMessage = [false, detail];
    }
    if (logLevel < lev) return;
    VsPluginLog.logInfo(dataStr + LEV_STR[lev] + detail);
}

VsPluginLog.logError = function (...args) {
    recordLog(VsPluginLog.LEV_ERROR, args);
}

VsPluginLog.logDebug = function (...args) {
    recordLog(VsPluginLog.LEV_DEBUG, args);
}

VsPluginLog.logInfo = function (...args) {
    recordLog(VsPluginLog.LEV_INFO, args);
}

VsPluginLog.getResult = function () {
    return logResultMessage;
}

module.exports = {
    VsPluginLog
}