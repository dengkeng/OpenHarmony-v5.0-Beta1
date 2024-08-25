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
let genDir = "../../src/gen/"
const { generateGYP } = require(genDir + "extend/binding_gyp");
const { generateGN } = require(genDir + "extend/build_gn");
const { generateBase } = require(genDir + "extend/tool_utility");
var assert = require("assert");
const { readFile } = require("../../src/gen/tools/FileRW");

describe('Extend', function () {

    it('test gen/extend/binding_gyp generateGYP', function () {
        generateGYP('test/unittest', 'napitest', '/*\n* Copyright (c) 2022 Shenzhen Kaihong\n*/');
        let data = readFile("test/unittest/binding.gyp")
        let retJson = JSON.stringify(data)
        let copyRight = retJson.substring(1, retJson.indexOf("Kaihong"))
        assert.strictEqual(copyRight, "# Copyright (c) 2022 Shenzhen ")
        let dataTest = readFile("test/unittest/test.sh")
        let retTest = JSON.stringify(dataTest)
        assert.strictEqual(retTest, "\"node-gyp configure build && sleep 0.5 && node --expose-gc test.js\"")

    });

    it('test gen/extend/build_gn generateGN', function () {
        var fs = require("fs");
        if (fs.existsSync('test/unittest/BUILD.gn')) {
            fs.unlink('test/unittest/BUILD.gn', function (err) {
                if (err) {
                    return console.error(err);
                }
            });
        }
        let Copyright = '/*\n* Copyright (c) 2022 Shenzhen Kaihong\n*/';
        generateGN('test/unittest', 'napitest', Copyright, 'input_sample');
        let data = readFile("test/unittest/BUILD.gn")
        let retJson = JSON.stringify(data)
        let copyRight = retJson.substring(1, retJson.indexOf("Kaihong"))
        assert.strictEqual(copyRight, "# Copyright (c) 2022 Shenzhen ")
    });

    partGenerateBase();
});

function partGenerateBase(){
    it('test gen/extend/tool_utility generateBase', function () {
        var fs = require("fs");
        if (fs.existsSync('test/unittest/tool_utility.cpp')) {
            fs.unlink('test/unittest/tool_utility.cpp', function (err) {
                if (err) {
                    return console.error(err);
                }
            });
        }
        if (fs.existsSync('test/unittest/tool_utility.h')) {
            fs.unlink('test/unittest/tool_utility.h', function (err) {
                if (err) {
                    return console.error(err);
                }
            });
        }
        generateBase('test/unittest', '/*\n* Copyright (c) 2022 Shenzhen Kaihong\n*/');
        let data = readFile("test/unittest/tool_utility.cpp")
        let retJson = JSON.stringify(data)
        let copyRight = retJson.substring(1, retJson.indexOf("Kaihong"))
        assert.strictEqual(copyRight, "/*\\n* Copyright (c) 2022 Shenzhen ")

        let data1 = readFile("test/unittest/tool_utility.h")
        let retJson1 = JSON.stringify(data1)
        let copyRight1 = retJson.substring(1, retJson1.indexOf("Kaihong"))
        assert.strictEqual(copyRight1, "/*\\n* Copyright (c) 2022 Shenzhen ")
    });

}
