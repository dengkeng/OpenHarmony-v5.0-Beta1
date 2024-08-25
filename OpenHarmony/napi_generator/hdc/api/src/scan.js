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
const xlsx = require("xlsx");
const fs = require("fs");
const path = require("path");
const stdio = require("stdio");

let ops = stdio.getopt({
    'directory': { key: 'd', args: 1, description: "scan directory" },
    'output': { key: 'o', args: 1, description: "output directory", default: "." },
});

let distDir = ops.directory;
let outDir = ops.output;

function union(a, b) {
    let ret = new Set();
    a.forEach((n1) => {
        ret.add(n1);
    });
    b.forEach((n1) => {
        ret.add(n1);
    });
    return ret;
}

function intersection(a, b) {
    let ret = new Set();
    a.forEach((n1) => {
        if (b.has(n1)) {
            ret.add(n1);
        }
    })
    return ret;
}

function collectFromSheet(sheet) {
    let row = 2;
    let collectInclude = new Set()
    let collectFunction = new Set()
    while (true) {
        let idx = "B" + row;
        if (!(idx in sheet)) {
            break;
        }
        collectInclude.add(sheet[idx].w);

        if (sheet["C" + row].w == "Function") {
            collectFunction.add(sheet["D" + row].w);
        }
        row += 1;
    }
    return [collectInclude, collectFunction]
}
let wb = xlsx.readFile(path.join(__dirname, "Andr_N_Games_api.xlsx"));

let c1 = collectFromSheet(wb.Sheets.Games);
let c2 = collectFromSheet(wb.Sheets.N);

let androidFeature = {
    include: union(c1[0], c2[0]),
    function: union(c1[1], c2[1]),
}
//////////////////////////////////////////////////////

let projectFiles = {
    c: [],
    cpp: [],
    h: [],
}

let projectFeature = {
    "function": new Set(),
    "include": new Set()
}

function collectFromFile(fn) {
    let data = fs.readFileSync(fn, { encoding: "utf8" });

    for (let ss of data.matchAll(/([A-Za-z_][A-Za-z0-9_]*) *\(/g)) {
        projectFeature["function"].add(ss[1]);
    }

    for (let ss of data.matchAll(/# *include *(<|") *([A-Za-z_][A-Za-z0-9_\-/]*(.h(pp)*)*) *(>|")/g)) {
        let s = ss[2].split("/");
        s = s[s.length - 1];
        projectFeature["include"].add(s);
    }
}

function collectFile (pth, f) {
    let fn = path.join(pth, f);
    let st;
    try {
        st = fs.statSync(fn);
    } catch(err){
        return;
    }
    if (st.isDirectory()) {
        collectFeature(fn);
    }
    else if (st.isFile()) {
        if (f.endsWith(".h")) {
            projectFiles.h.push(fn);
            collectFromFile(fn);
        }
        else if (f.endsWith(".cpp")) {
            projectFiles.cpp.push(fn);
            collectFromFile(fn);
        }
        else if (f.endsWith(".c")) {
            projectFiles.c.push(fn);
            collectFromFile(fn);
        }
    }
} 

function collectFeature(pth) {
    let files = fs.readdirSync(pth);

    for (let f of files) {
        collectFile(pth, f);
    }   
}

collectFeature(distDir)

let result = {
    function: intersection(androidFeature["function"], projectFeature["function"]),
    include: intersection(androidFeature["include"], projectFeature["include"]),
}
console.log(result);
///////////////////////////////save to excel
function string2u8buff(s) {
    let buf = new ArrayBuffer(s.length);
    let view = new Uint8Array(buf);
    for (let i = 0; i !== s.length; ++i) {
        view[i] = s.charCodeAt(i) & 0xff;
    }
    return view;
}

let wopts = {
    bookType: "xlsx",
    bookSST: false,
    type: 'binary'
};
let workbook = xlsx.utils.book_new();

let s1 = []
for (let f of result.function) {
    s1.push({ function: f })
}
let sheet1 = xlsx.utils.json_to_sheet(s1);
xlsx.utils.book_append_sheet(workbook, sheet1, 'sheet1');

let s2 = []
for (let f of result.include) {
    s2.push({ include: f })
}
let sheet2 = xlsx.utils.json_to_sheet(s2);
xlsx.utils.book_append_sheet(workbook, sheet2, 'sheet2');

let wbout = xlsx.write(workbook, wopts);
let ddd = string2u8buff(wbout);
let outPath = path.join(outDir, "result.xlsx");
console.log("output:", outPath);
fs.writeFileSync(outPath, ddd);
