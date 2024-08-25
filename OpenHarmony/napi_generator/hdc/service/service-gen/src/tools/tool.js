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
let vscode = null;
try {
    vscode = require('vscode');
}
catch (err) {
    vscode = null;
}

function print(...args) {
    if (vscode) {
        vscode.window.showInformationMessage(...args);
    }
    console.log(...args);
}

String.prototype.format = function (...args) {
    var result = this;
    let reg = new RegExp("%[sd]{1}")
    for (let i = 0; i < args.length; i++) {
        let p = result.search(reg);
        if (p < 0) break;
        result = result.substring(0, p) + args[i] + result.substring(p + 2, result.length);
    }
    return result;
}

String.prototype.replaceAll = function (...args) {
    let result = this;
    while (result.indexOf(args[0]) >= 0) {
        result = result.replace(args[0], args[1]);
    }
    return result;
}

function replaceAll(s, sfrom, sto) {
    while (s.indexOf(sfrom) >= 0) {
        s = s.replace(sfrom, sto);
    }
    return s;
}

function getTab(tabLv) {
    let tab = "";
    for(var i = 0; i < tabLv; ++i) {
        tab += "    ";
    }
    return tab;
}

module.exports = {
    replaceAll,
    print,
    getTab
}
