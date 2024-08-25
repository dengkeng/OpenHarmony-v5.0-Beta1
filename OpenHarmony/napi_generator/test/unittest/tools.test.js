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
const { readFile, writeFile } = require(genDir + "tools/FileRW");
const { getArrayType, getArrayTypeTwo } = require(genDir + "tools/common");
const { isEnum, enumIndex, getMapType,checkFileError } = require(genDir + "tools/common");
const { search, match, removeReg, getReg} = require(genDir + "tools/re");
const {  replaceAll, all } = require(genDir + "tools/re");
const { checkOutBody, removeExplains,replaceTab } = require(genDir + "tools/tool");
const { removeEmptyLine, print,getLicense,removeEmptyLine2 } = require(genDir + "tools/tool");
const assert = require("assert");
const rewire = require("rewire");
const { json } = require("stream/consumers");

var correctResult;

function before(){
    let data = readFile("test/unittest/result.json")
        if (data) {
            correctResult = JSON.parse(data);
        }
}
describe('Tools', function () {
   
    before(function () {
        before();
    });

    it('test gen/tools/re search', function () {
        let ret = search('@ohos([.a-z_A-Z0-9]+).d.ts','@ohos.input_sample.d.ts');
        assert.strictEqual(JSON.stringify(ret), `{"regs":[[0,23],[5,18]]}`);
    });

    it('test gen/tools/re match', function () {
        let ret = match('@ohos([.a-z_A-Z0-9]+).d.ts','@ohos.input_sample.d.ts');
        assert.strictEqual(JSON.stringify(ret),  `{"regs":[[0,23],[5,18]]}`);
    });
      
    partOfReTest();

    partOfCommonTest();

    partOfToolsTest(correctResult);

    it('test gen/tools/tool removeExplains', function () {
        let param = correctResult['ParamIn']['removeExplains'];
        let ret = removeExplains(param);
        let result = correctResult['tools']['removeExplains'];
        assert.strictEqual(JSON.stringify(ret), JSON.stringify(result));
    });

    it('test gen/tools/FileRW readFile', function () { 
        let aaa = Math.random()*10000
        let content="时间 = %^(^*%*&^*"+aaa;
        writeFile("test/unittest/testrw.txt",content);
        let ret = readFile("test/unittest/testrw.txt")
        assert.strictEqual(ret, content);
    });

});

function partOfReTest(){   
    it('test gen/tools/re removeReg', function () {
        let ret = removeReg('export default napitest;',[4, 22]);
    
        assert.strictEqual(JSON.stringify(ret), `"expot;"`);
    });
    
    it('test gen/tools/re getReg', function () {
        let data = 'declare namespace napitest {function fun6(v2: string): void;}export default napitest;';
        assert.strictEqual(JSON.stringify(getReg(data,[0, 10])), `"declare na"`);
    });
    
    it('test gen/tools/re replaceAll', function () {
        let ret = replaceAll('\n *//([a-zA-Z .]+)\n','\\.','\\.');
        let retJson = JSON.stringify(ret)
        assert.strictEqual(retJson, `"\\n *//([a-zA-Z \\\\.]+)\\n"`);
    });
    
    it('test gen/tools/re all', function () {
        assert.strictEqual(JSON.stringify(all('\\.')), "{}");
    });
    }
    
    function partOfCommonTest() {
        it('test gen/tools/common getArrayType', function () {
            let ret = getArrayType('Array<number>');
            assert.strictEqual(ret, 'number');
        });
    
        it('test gen/tools/common getArrayTypeTwo', function () {
            let ret = getArrayTypeTwo('string[]');
            assert.strictEqual(ret, 'string');
        });
    
        it('test gen/tools/common isEnum', function () {
            let enumElement = [{name:"STATUS0",value:"0",type:"NUMBER_TYPE_1"}];
            let data = {
                class: [],
                const: [],
                enum: [{name:"HttpStatus",body:{element:enumElement,function:[],enumValueType:0}}],
                exports: ['HttpStatus'],
                function: [],
                interface: [],
                namespace: [],
            }
            let ret = isEnum('HttpStatus', data);
            assert.strictEqual(ret, true);
        });
    
        it('test gen/tools/common enumIndex', function () {
            let enumElement = [{name:"STATUS0",value:"0",type:"NUMBER_TYPE_1"}];
            let data = {
                class: [],
                const: [],
                enum: [{name:"HttpStatus",body:{element:enumElement,function:[],enumValueType:0}}],
                exports: ['HttpStatus'],
                function: [],
                interface: [],
                namespace: [],
            }
            let ret = enumIndex('HttpStatus', data);
            assert.strictEqual(ret, '0');
        });
    
        partOfCommonTwo();
    }
    
    function partOfCommonTwo(){
        it('test gen/tools/common getMapType', function () {
            let result = [ 'string', 'NUMBER_TYPE_1', undefined, undefined ];
            let ret = getMapType('{[key:string]:NUMBER_TYPE_1}');
            assert.strictEqual(JSON.stringify(ret), JSON.stringify(result));
        });
    
        it('test gen/tools/common checkFileError', function () {
            let result = [
                false,
                "File 'napi_generator-master/test/unittest/@ohos.input_sample.d.ts' not found.\n" +
                  '  The file is in the program because:\n' +
                  '    Root file specified for compilation\n'
              ];
            let ret = checkFileError('napi_generator-master\\test\\unittest\\@ohos.input_sample.d.ts');
            this.timeout(5000)
            assert.strictEqual(JSON.stringify(ret), JSON.stringify(result));
        });
    }
    
    function partOfToolsTest(correctResult) {
        it('test gen/tools/tool print', function () {
            let lib = rewire(genDir+'tools/tool.js');
            let print = lib.__get__("print");
            print("tool test print");
        });
    
        it('test gen/tools/tool checkOutBody', function () {
            let body = correctResult['ParamIn']['checkOutBody'];
            let ret = checkOutBody(body,27,null,true);
            let result = "function fun1(v1: { [key: string]: Array<string> }):void;";
            assert.strictEqual(JSON.stringify(ret), JSON.stringify(result));
        });
    
        it('test gen/tools/tool removeEmptyLine', function () {  
            param = correctResult['ParamIn']['removeEmptyLine'];
            let retJson = JSON.stringify(removeEmptyLine(param))
            let result = 'declare namespace napitest {\nfunction fun1(v1: string):void;\n}\nexport default napitest;\n';
            assert.strictEqual(retJson, JSON.stringify(result));
        });
    
        it('test gen/tools/tool getLicense', function () {  
            param = correctResult['ParamIn']['getLicense'];
            let retJson = JSON.stringify(getLicense(param))
            let result = '/*\n* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. \n*/';
            assert.strictEqual(retJson, JSON.stringify(result));
        });
    
        it('test gen/tools/tool replaceTab', function () {  
            param = 'declare namespace napitest {\tfunction fun1():void;}export default napitest;';
            let retJson = JSON.stringify(replaceTab(param))
            let result = 'declare namespace napitest {    function fun1():void;}export default napitest;';
            assert.strictEqual(retJson, JSON.stringify(result));
        });
    
        it('test gen/tools/tool replaceAll', function () {
            param = correctResult['toolsParam']['replaceAll']
            let ret = replaceAll(JSON.stringify(param),'[funcName]','if_direct');
            assert.strictEqual(JSON.stringify(ret), correctResult['tools']['replaceAll']);
        });
    }