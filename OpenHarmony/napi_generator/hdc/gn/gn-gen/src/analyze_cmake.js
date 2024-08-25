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
const path = require("path");
const { Logger } = require("./logger");
const { Tool } = require("./tool");
const childProcess = require("child_process");
const fs = require("fs");
const { AnalyzeMake } = require("./analyze_make");

class AnalyzeCMake {
    constructor() {

    }
    static mkdirBuildTemp(compileFile){
        let buildTmp;
        if(Tool.OHOS_PORTING_TO==""){
            buildTmp = path.join(compileFile.dir, "build_tmp");//cmake编译的临时目录
        }
        else{
            buildTmp = path.join(Tool.OHOS_PROJECT_PATH,Tool.OHOS_PORTING_TO, "build_tmp");//cmake编译的临时目录
        }
        if (fs.existsSync(buildTmp)) {
            fs.rmSync(buildTmp, { recursive: true, force: true });//🌻
        }
        return buildTmp;
    }

    static analyze(compileFile, cmakeArgs) {//在工程目录创建一个buildTmp目录，执行cmake初始化工程，执行make得到命令行序列
        if (!fs.existsSync(path.join(Tool.OHOS_PROJECT_PATH, Tool.OHOS_PRODUCT_OUTPUT_PATH, "build.ninja"))) {
            Logger.err("param ohos need to looks like out/rk3568");
            return;
        }
        let buildTmp = AnalyzeCMake.mkdirBuildTemp(compileFile);
        fs.mkdirSync(buildTmp);
        Tool.pushd(buildTmp);
        let ohosToolchainCmake = Tool.getCMakeToolchain();
        let ohosToolchainCmakeData = fs.readFileSync(ohosToolchainCmake, { encoding: "utf8" });
        while (ohosToolchainCmakeData.indexOf("CC_REPLACE_OHOS_ROOT") >= 0) {
            ohosToolchainCmakeData = ohosToolchainCmakeData.replace("CC_REPLACE_OHOS_ROOT",
                Tool.swapPath(Tool.OHOS_PROJECT_PATH, true));
        }
        while (ohosToolchainCmakeData.indexOf("CC_REPLACE_OHOS_TARGET") >= 0) {
            ohosToolchainCmakeData = ohosToolchainCmakeData.replace("CC_REPLACE_OHOS_TARGET",
                Tool.OHOS_PRODUCT_OUTPUT_PATH);
        }
        ohosToolchainCmake = path.join(buildTmp, "ohos.toolchain.cmake");
        fs.writeFileSync(ohosToolchainCmake, ohosToolchainCmakeData);
        ohosToolchainCmake=Tool.swapPath(ohosToolchainCmake);
        let args = [compileFile.dir,
            "-DCMAKE_TOOLCHAIN_FILE=%s".format(ohosToolchainCmake),"-G","Unix Makefiles",
            "-DCMAKE_MAKE_PROGRAM=%s".format(Tool.swapPath(Tool.getMakeRaw())),
        ];
        if (cmakeArgs.length > 0) {
            args.push(...cmakeArgs.split(","));
        }
        let ret = childProcess.spawn(Tool.swapPath(Tool.getCMake()), args);
        ret.stdout.on('data', (data) => {
            Logger.info(data.toString());
        });
        ret.stderr.on('data', (data) => {
            Logger.err(data.toString(), true);
        });
        ret.on('close', (code) => {
            if (code == 0) {
                Logger.info("------------------------cmake ok");
                AnalyzeMake.analyze(path.join(buildTmp, "Makefile")); //调用make生成命令行
            }
            else Logger.err("cmake fail");
        })
    }
}

module.exports = {
    AnalyzeCMake
}