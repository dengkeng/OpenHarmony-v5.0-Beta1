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
const fs = require("fs");
const { Logger } = require("./logger");
const { Tool } = require("./tool");
const { exit } = require("process");

function saveMockData(projectPath, analyzeResult) {
    let ss = JSON.stringify({
        projectPath: projectPath,
        analyzeResult: analyzeResult
    }, null, 4);
    fs.writeFileSync(path.join(Tool.CURRENT_TOOL_PATH, "mock.json"), ss)
    Logger.err("save mock exit");
}

function preProcessResult(analyzeResult) {//把所有路径搞成绝对路径
    for (let r of analyzeResult) {
        if (!r.target.startsWith("/")) {
            if (!path.isAbsolute(r.target)) {
                r.target = path.join(r.workDir, r.target);
            }
        }
        for (let i = 0; i < r.inputs.length; i++) {
            if (r.inputs[i].startsWith('"') && r.inputs[i].endsWith('"')) {
                r.inputs[i] = r.inputs[i].substring(1, r.inputs[i].length - 1);
            }
            if (!r.inputs[i].startsWith("/")) {
                if (!path.isAbsolute(r.inputs[i])) {
                    r.inputs[i] = path.join(r.workDir, r.inputs[i]);
                }
            }
        }
        for (let i = 0; i < r.includes.length; i++) {
            if (!r.includes[i].startsWith("/")) {
                if (!path.isAbsolute(r.includes[i])) {
                    r.includes[i] = path.join(r.workDir, r.includes[i]);
                }
            }
        }
    }
}

function checkoutLibName(name) {//比如/home/libabc.so，返回["dynamic",abc]
    let pn = path.parse(name);
    let tname = pn.base;
    if (tname.endsWith(".a")) {
        tname = tname.substring(0, tname.length - 2);
        if (tname.startsWith("lib")) {
            tname = tname.substring(3);
        }
        return ["static", tname];
    }
    else if (tname.endsWith(".so") || tname.indexOf(".so.") > 0) {
        tname = tname.substring(0, tname.indexOf(".so"));
        if (tname.startsWith("lib")) {
            tname = tname.substring(3);
        }
        return ["dynamic", tname];
    }
    else {
        return ["executable", tname];
    }
}

class GenerateGn {
    constructor() {
    }

    static mockGenerate() {
        let ss = fs.readFileSync(path.join(Tool.CURRENT_TOOL_PATH, "mock.json"), { encoding: "utf8" });
        let ret = JSON.parse(ss);
        GenerateGn.generate(ret.projectPath, ret.analyzeResult);
        Logger.err("generate mock exit")
    }

    static generate(projectPath, analyzeResult) {
        if (Tool.MOCK_TYPE == Tool.MOCK_ENUM.MOCK_RECORD) {
            saveMockData(projectPath, analyzeResult);//保存mock数据
        }

        preProcessResult(analyzeResult);

        let genList = {};
        for (let ret of analyzeResult) {
            if (ret) {
                if (ret.workDir in genList) {//根据目录分类genList，每个目录生成一个BUILD.gn
                    genList[ret.workDir].push(ret);
                }
                else {
                    genList[ret.workDir] = [ret];
                }
            }
        }
        let num = 0;
        for (let gnPath in genList) {//genList的key即为需要生成gn的目录
            Logger.info("%d-------------------generate dir %s".format(num, gnPath));
            GenerateGn.generateGn(gnPath, genList, projectPath);
            num++;
        }
        GenerateGn.generateTargetGroup(projectPath);
        Logger.info("-------------------generate gn ok");
    }
    static COLLECT_TARGET = {
        static: [],
        dynamic: [],
        executable: []
    }
    static generateTargetGroup(projectPath) {
        let gnName = path.join(projectPath, "BUILD.gn");
        let gnStr = 'import("//build/ohos.gni")\n\n';
        if (fs.existsSync(gnName)) {
            gnStr = fs.readFileSync(gnName, { encoding: "utf8" });
        }

        let staticTargets = [];
        for (let t of GenerateGn.COLLECT_TARGET.static) {
            staticTargets.push(Tool.swapPath(t.path) + ":" + t.name);
        }
        let dynamicTargets = [];
        for (let t of GenerateGn.COLLECT_TARGET.dynamic) {
            dynamicTargets.push(Tool.swapPath(t.path) + ":" + t.name);
        }
        let executableTargets = [];
        for (let t of GenerateGn.COLLECT_TARGET.executable) {
            executableTargets.push(Tool.swapPath(t.path) + ":" + t.name);
        }

        gnStr += `
group("all_targets") {
    deps = [`
        if (staticTargets.length > 0) {
            gnStr += `
        #静态库
        "%s",
`.format(staticTargets.join('",\n        "'));
        }
        if (dynamicTargets.length > 0) {
            gnStr += `
        #动态库
        "%s",
`.format(dynamicTargets.join('",\n        "'));
        }
        if (executableTargets.length > 0) {
            gnStr += `
        #可执行程序
        "%s",
`.format(executableTargets.join('",\n        "'));
        }
        gnStr += `
    ]
}
`
        while (gnStr.indexOf(Tool.OHOS_PROJECT_PATH) >= 0) {
            gnStr = gnStr.replace(Tool.OHOS_PROJECT_PATH, "/");
        }
        fs.writeFileSync(gnName, gnStr, { encoding: "utf8" });
    }
    static genTargetStr(targetName) {
        switch (targetName[0]) {
            case "static":
                return 'ohos_static_library("' + targetName[1] + '")';
            case "dynamic":
                return 'ohos_shared_library("' + targetName[1] + '")';
            case "executable":
                return 'ohos_executable("' + targetName[1] + '")';
        }
    }
    static genCollectDetail(gen, genList) {
        let collectDetails = {
            cflags: new Set(),
            cflagsCc: new Set(),
            sources: new Set(),
            includeDirs: new Set(),
            defines: new Set(),
            deps: new Set(),
        }
        for (let absDepTarget of gen.inputs) {
            GenerateGn.collectFromGList(absDepTarget, genList, collectDetails);
        }
        return collectDetails;
    }
    static genTargetStr2(collectDetails, targetStr, targetName) {
        if (collectDetails.cflags.size > 0 || collectDetails.cflagsCc.size > 0) {//放到config里面才生效
            let configDetail = "";
            let removeConfigs = "";
            if (collectDetails.cflags.size > 0) {
                configDetail += GenerateGn.genDetail("cflags", collectDetails.cflags);
            }
            if (collectDetails.cflagsCc.size > 0) {
                configDetail += GenerateGn.genDetail("cflags_cc", collectDetails.cflagsCc);
            }
            if (collectDetails.cflags.has("-frtti")) {
                removeConfigs += `        "//build/config/compiler:no_rtti",\n`
            }
            if (collectDetails.cflags.has("-fexceptions")) {
                removeConfigs += `        "//build/config/compiler:no_exceptions",\n`
            }
            targetStr = `config("%s_config") {%s}

%s
remove_configs = [
%s    ]
configs = [ ":%s_config" ]
`.format(targetName[1], configDetail, targetStr, removeConfigs, targetName[1]);
        }
        if (collectDetails.sources.size > 0) {
            targetStr += GenerateGn.genDetail("sources", collectDetails.sources);
        }
        if (collectDetails.includeDirs.size > 0) {
            targetStr += GenerateGn.genDetail("include_dirs", collectDetails.includeDirs);
        }
        if (collectDetails.defines.size > 0) {
            targetStr += GenerateGn.genDetail("defines", collectDetails.defines);
        }
        if (collectDetails.deps.size > 0) {
            targetStr += GenerateGn.genDetail("deps", collectDetails.deps);
        }

        targetStr += `
part_name = "%s"
subsystem_name = "%s"
}

`.format(Tool.OHOS_PART_NAME, Tool.OHOS_SUBSYSTEM_NAME);
        return targetStr;
    }
    static generateGn(gnPath, genList, projectPath) {
        if (!gnPath.startsWith(projectPath)) {
            Logger.err("target path not in project path\ntarget:%s\nproject:%s".format(gnPath, projectPath))
        }
        let gnStr = 'import("//build/ohos.gni")\n\n';
        let targetCount = 0;
        let gens = genList[gnPath];
        for (let gen of gens) {//枚举在gnPath下的目标
            if (gen.isLink) {//不是链接，不生成目标
                let targetName = checkoutLibName(gen.target);
                let targetStr = GenerateGn.genTargetStr(targetName) + '\n{';

                GenerateGn.COLLECT_TARGET[targetName[0]].push({
                    path: gnPath,
                    name: targetName[1]
                });
                let collectDetails = GenerateGn.genCollectDetail(gen, genList);
                targetStr = GenerateGn.genTargetStr2(collectDetails, targetStr, targetName);

                gnStr += targetStr;
                targetCount++;
            }
        }

        if (targetCount > 0) {
            let gnName = path.join(gnPath, "BUILD.gn");
            Logger.info("输出：" + gnName + "\n" + gnStr);
            fs.writeFileSync(gnName, gnStr, { encoding: "utf8" });
        }
        else {
            Logger.info("          no target");
        }
    }

    static genDetail(name, detail) {
        let ss = ""
        for (let s of detail) {
            s=Tool.swapPath(s);
            if (ss.length > 0) ss += '",\n        "';
            ss += s;
        }
        let ret = `
    %s = [
        "%s"
    ]
`.format(name, ss)

        while (ret.indexOf(Tool.OHOS_PROJECT_PATH) >= 0) {
            ret = ret.replace(Tool.OHOS_PROJECT_PATH, "/");
        }
        return ret;
    }

    static searchLib(name, genList) {
        for (let gnPath in genList) {
            let gens = genList[gnPath]
            for (let gen of gens) {
                if (gen.target == name) {
                    let tt = checkoutLibName(gen.target);
                    return gen.workDir + ":" + tt[1];
                }
            }
        }
        return null;
    }

    static collectGen2(gen, collectDetails) {
        let collectFileStat = 0;
        for (let a of gen.cflags) {
            let badd = true;
            switch (collectFileStat) {
                case 0:
                    if (a == "-Xclang") {
                        collectFileStat = 1;
                        badd = false;
                    }
                    break;
                case 1:
                    if (a == "-include" || a == "-include-pch") {
                        collectFileStat = 2;
                        badd = false;
                    }
                    else {
                        collectDetails.cflags.add("-Xclang");
                        collectFileStat = 0;
                    }
                    break;
                case 2:
                    if (a == "-Xclang") {
                        collectFileStat = 3;
                        badd = false;
                    }
                    else {
                        collectFileStat = 0;
                    }
                    break;
                case 3://预编译文件加入进来一起编译
                    GenerateGn.collectFromGList(a, genList, collectDetails);
                    collectFileStat = 0;
                    badd = false;
                    break;
            }

            if (badd) {
                collectDetails.cflags.add(a);
            }
        }
    }
    static collectGen(gen, genList, collectDetails) {
        for (let i of gen.inputs) {
            if (!(i.endsWith('.c') || i.endsWith('.cpp') || i.endsWith('.cxx') || i.endsWith('.cc'))) {
                GenerateGn.collectFromGList(i, genList, collectDetails);
            } else {
                collectDetails.sources.add(i);
                for (let a of gen.includes) {
                    collectDetails.includeDirs.add(a);
                }
                for (let a of gen.defines) {
                    collectDetails.defines.add(a);
                }
                GenerateGn.collectGen2(gen, collectDetails);
                console.log(gen);
                for (let a of gen.cflagsCc) {
                    collectDetails.cflagsCc.add(a);
                }
            }
        }
    }
    static collectFromGList(name, genList, collectDetails) {//获取依赖
        if (name.endsWith('.a') || name.endsWith('.so') || name.indexOf('.so.') > 0) {
            let dep = GenerateGn.searchLib(name, genList);
            if (dep) {//找到依赖，设置依赖
                collectDetails.deps.add(dep);
            }
            else {//没找到，让用户判断，依赖识别
                collectDetails.deps.add(name);
            }
            return;
        }
        if (name.endsWith('.c')) {
            collectDetails.sources.add(name);
        }
        for (let gnPath in genList) {
            let gens = genList[gnPath]
            for (let gen of gens) {
                if (name.endsWith(gen.target)) {
                    GenerateGn.collectGen(gen, genList, collectDetails);
                }
            }
        }
    }
}

module.exports = {
    GenerateGn
}
