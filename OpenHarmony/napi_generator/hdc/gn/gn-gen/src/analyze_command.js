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
const { Logger } = require("./logger");
const fs = require("fs");
const path = require("path");
const { Tool } = require("./tool");

class AnalyzeCommand {
    constructor() {

    }

    static isCmd(cmd, name) {
        let cmdName = cmd.split(" ")[0];
        let v1 = cmdName.endsWith(name);
        let v2 = cmdName.endsWith(name + ".exe");
        return v1 || v2;
    }

    static COMPILE_CMDS = {
        "clang": 0,
        "ar": 1,
        "clang++": 2
    };

    static COLLECT_COMMANDS = [];
    static storeCommands() {
        fs.writeFileSync(path.join(Tool.CURRENT_TOOL_PATH, "cmds.txt"),
            AnalyzeCommand.COLLECT_COMMANDS.join("\n"), { encoding: "utf8" });
    }
    static getCompileCmdId(cmd) {
        let cmdName = cmd.split(" ")[0];
        for (let c in AnalyzeCommand.COMPILE_CMDS) {
            if (cmdName.endsWith(c) || cmdName.endsWith(c + ".exe")) {
                return AnalyzeCommand.COMPILE_CMDS[c];//返回命令ID
            }
        }
        return -1;
    }
    static analyze(cmd) {
        let cmds;
        if (cmd.indexOf("&&") >= 0) {
            cmds = cmd.split("&&");
        }
        else {
            cmds = [cmd];
        }
        let result = [];
        Tool.backupd(0);
        for (let c of cmds) {
            let ret = AnalyzeCommand.analyzeOneCmd(c);
            if (ret) {
                result.push(...ret);
            }
        }
        Tool.recoverd(0);
        return result;
    }
    static exAnalyzeCmake(cmd) {
        let ss = cmd.split(" ");
        if (ss.indexOf("-P") > 0) {//需要 cmake执行脚本，在这里直接执行 or 移到BUILD.gn里面执行
            const childProcess = require("child_process");
            childProcess.execSync(cmd);
            AnalyzeCommand.COLLECT_COMMANDS.push(cmd);
            return false;
        }
        let cmakeLinkScriptOffset = ss.indexOf("cmake_link_script");
        if (cmakeLinkScriptOffset >= 0) {//需要 这里可能要做一些错误判断
            let cmakeLinkScriptFile = ss[cmakeLinkScriptOffset + 1];
            let cmakeLinkScriptData = fs.readFileSync(path.join(process.cwd(), cmakeLinkScriptFile),
                { encoding: "utf8" });
            let cmds = cmakeLinkScriptData.split("\n");//link.txt中可能有多条命令链接
            let rets = []
            for (let c of cmds) {
                let r = AnalyzeCommand.analyzeOneCmd(c);
                if (r) {
                    rets.push(...r);
                }
            }
            if (rets.length > 0) {
                return rets;
            }
            else {
                return false;
            }
        }
        return false;
    }
    static isCmdScriptWithVersion(cmd, cmdType) {
        let cmdName = cmd.split(" ")[0];
        let pos = cmdName.lastIndexOf("/");
        let scrType = cmdName.substring(pos + 1, cmdName.length);
        return scrType.startsWith(cmdType)
    }

    static analyzeOneCmd(cmd) {
        while (cmd.startsWith("\n") || cmd.startsWith(" ")) {
            cmd = cmd.substring(1);
        }
        if (cmd.length <= 0) {
            return false;
        }
        if (cmd.match("^make(\\[\\d+\\]:)|: (Entering)|(Leaving) directory")) {//跳过进出目录的log
            //需要 改变工作目录
            return false;
        }
        if (cmd.startsWith("cd ")) {
            let t = AnalyzeCommand.splitString(cmd);
            Tool.pushd(t[1]);//改变工作目录
            return false;
        }
        if (AnalyzeCommand.isCmd(cmd, "ccache")) {//去掉ccache头
            cmd = cmd.substring(cmd.indexOf("ccache") + "ccache".length);
            return AnalyzeCommand.analyzeOneCmd(cmd);
        }
        if (AnalyzeCommand.isCmd(cmd, "cmake")) {//跳过cmake的log，需要解析link命令行
            return AnalyzeCommand.exAnalyzeCmake(cmd);
        }
        if (AnalyzeCommand.isCmd(cmd, "make") ||
            AnalyzeCommand.isCmd(cmd, "ranlib")) {//跳过这些命令
            return false;
        }
        if (AnalyzeCommand.getCompileCmdId(cmd) >= 0) {//解析编译命令行
            AnalyzeCommand.COLLECT_COMMANDS.push(cmd);
            return [AnalyzeCommand.analyzeCompileCommand(cmd)];
        }
        if (AnalyzeCommand.isCmd(cmd, "perl") ||
            AnalyzeCommand.isCmd(cmd, "autoreconf") ||
            AnalyzeCommand.isCmdScriptWithVersion(cmd, "python")) {
            // 需要即时执行（可能会生成依赖源文件），如果不执行，后续编译命令可能会报错，找不到源文件
            Logger.info(cmd);
            const childProcess = require("child_process");
            childProcess.execSync(cmd);
            return false;
        }
        Logger.err("未解析的命令行:" + cmd);
        return false;
    }

    static resultTemplete() {//解析命令行之后的结果模板
        return {
            type: 0,//0 compile command,1 other command
            workDir: process.cwd(),
            command: "",
            inputs: [],
            target: "",
            isLink: false,//是否编译，.a/.o/可执行程序，需要生成目标
            includes: [],
            defines: [
                "_XOPEN_SOURCE=600",//ohos的编译环境缺失宏
                "FE_TONEAREST=0x00000000",
                "FE_UPWARD=0x00400000",
                "FE_DOWNWARD=0x00800000",
                "FE_TOWARDZERO=0x00c00000",
            ],
            cflags: [
                "-Wno-implicit-function-declaration",
                "-Wno-unused-function",
                "-Wno-comments",//允许注释后面有个\
                "-Wno-string-conversion",//允许char*当做bool使用
                "-Wno-header-hygiene",//不检测命名空间污染
                "-frtti",//支持typeid(xxx)
                "-fexceptions",//支持try catch
            ],//c和c++选项
            cflagsCc: [],//c++选项
            cflagsC: [],//c选项
        }
    }

    static splitString(s) {//按空格分割字符串
        let ret = [];
        let startp = -1;
        let isContinuChar = 0;
        for (let p = 0; p < s.length; p++) {
            if (s[p] == "\"" && s[p-1] != "\\") {
                isContinuChar = 1 - isContinuChar;
            }
            if (startp >= 0) {
                if (s[p] == ' ' && isContinuChar == 0) {
                    ret.push(s.substring(startp, p));
                    startp = -1;
                }
            }
            else if (s[p] != ' ') {
                startp = p;
            }
        }
        if (startp >= 0) {
            ret.push(s.substring(startp));
        }
        return ret;
    }

    static mockTarget(t) {
        if (t.target) {
            fs.writeFileSync(t.target, " ");
        }
    }
    static clangCheck1(e) {
        let ss = ["--sysroot=",
            "-pthread",
            "-Qunused-arguments",
            "-ffunction-sections",
            "-fdata-sections",
            "-fvisibility=hidden",
            "-fvisibility-inlines-hidden",
            "-O3",
            "-Os",
            "-fPIC",
            "-pedantic",
            "-fwrapv",
            "-shared",
            "-lm",
            "-lpthread",
            "-lz",
            "-MD",
            "-isystem"
        ];
        for (let s of ss) {
            if (e.startsWith(s) || e == "-w") {
                return true;
            }
        }
        return false;
    }
    static clangCheck2(local, e) {
        if (e.startsWith("-MT") || e.startsWith("-MF")) {
            if (e.length == 3) {
                local.p++;
            }
            return true;
        }

        if (e.startsWith("-s")) {
            if (e.length == 2) {
                local.p++;
            }
            return true;
        }
        return false;
    }
    static clangCheck3(local, e) {
        if (e.startsWith("-D")) {//需要记录到defines里面的参数
            //需要 是否-D开头的，全部记录到defines里面
            if (e.length == 2) {//-D xxx
                local.ret.defines.push(local.eles[local.p++]);
            }
            else {//-Dxxx
                local.ret.defines.push(e.substring(2));
            }
            return true;
        }
        return false;
    }
    static clangCheck4(local, e) {
        if (e.startsWith("-I")) {//需要记录到includes的参数
            if (e.length == 2) {//-I xxx
                local.ret.includes.push(local.eles[local.p++]);
            }
            else {//-Ixxx
                local.ret.includes.push(e.substring(2));
            }
            return true;
        }
        return false;
    }
    static validCFlag(cflag, allowedFlag) {
        for (let i = 0; i < allowedFlag.length; ++i) {
            if (cflag.startsWith(allowedFlag[i])) {
                return true;
            }
        }
        return false;
    }
    static clangCheck5(local, e) {
        if (this.validCFlag(e, Tool.getAllowedC().compileflag) || (e == "-D__clang__")) {
            local.ret.cflags.push(e); //需要记录到flags里面的参数
            return true;
        }
        return false;
    }
    static clangCheck6(local, e) {
        if (e == "-o") {
            if (e.length == 2) {//-o xxx
                local.ret.target = local.eles[local.p++];
            }
            else {//-oxxx
                local.ret.target = e.substring(2);
            }
            if (local.ret.target.endsWith(".a") ||
                local.ret.target.endsWith(".so") ||
                (!e.endsWith(".c") && !e.endsWith(".o"))) {
                local.ret.isLink = true;
            }
            return true;
        }
        return false;
    }

    static clangCheck7(local, e) {
        if (this.validSuffix(e, Tool.getAllowedC().fileSuffix)) {
            local.ret.inputs.push(e);
            return true;
        }
        if (e.endsWith(".rsp")) {
            console.log(Tool.CURRENT_DIR);
            let rspth = path.join(Tool.CURRENT_DIR, e.substring(1));
            let data = fs.readFileSync(rspth, { encoding: "utf8" });
            if (data.endsWith("\r\n")) {
                data = data.substring(0, data.length - 2);
            }
            let datas = data.split(" ");
            for (let d of datas) {
                for (let s of ss) {
                    if (d.endsWith(s)) {
                        local.ret.inputs.push(d);
                    }
                }
            }
            return true;
        }
        return false;
    }

    static analyzeCcClang(cmd) {
        let local = {
            ret: AnalyzeCommand.resultTemplete(),
            eles: AnalyzeCommand.splitString(cmd),
            p: 0,
        }

        while (local.p < local.eles.length) {
            let e = local.eles[local.p++];
            if (e.endsWith("clang") || e.endsWith("clang.exe")) {
                local.ret.command = e;
            }
            else if (AnalyzeCommand.clangCheck1(e)) { }
            else if (AnalyzeCommand.clangCheck2(local, e)) { }
            else if (e.startsWith("-Wl,--dynamic-linker,") || e.startsWith("-rdynamic")) {//-----直接忽略的链接参数
                local.ret.isLink = true;
            }
            else if (AnalyzeCommand.clangCheck3(local, e)) { }
            else if (AnalyzeCommand.clangCheck4(local, e)) { }
            else if (AnalyzeCommand.clangCheck5(local, e)) { }
            else if (e.startsWith("-std=")) {
                local.ret.cflagsCc.push(e);
            }
            else if (e.startsWith("-W")) {//需要 -W开头的怎么处理,-W -Wall -Werror=return-type -Wno-unnamed-type-template-args
                if (e.startsWith("-Wno-")) {
                    local.ret.cflags.push(e);
                }
            }
            else if (AnalyzeCommand.clangCheck6(local, e)) { }
            else if (e == "-c") {//编译
                local.ret.isLink = false;
            }
            else if (AnalyzeCommand.clangCheck7(local, e)) { }
            else {
                Logger.err(cmd + "\nclang未解析参数 " + e);
                process.exit();
            }
        }
        Logger.info("----clang-----" + local.ret.workDir + "\n\t" + local.ret.isLink + "," + local.ret.target)
        return local.ret;
    }
    static analyzeCcAr(cmd) {
        if (cmd.endsWith("\r")) {
            cmd = cmd.substring(0, cmd.length - 1);
        }
        let ret = AnalyzeCommand.resultTemplete();
        let eles = AnalyzeCommand.splitString(cmd);
        ret.isLink = true;
        let p = 0;
        while (p < eles.length) {
            let e = eles[p++];
            if (e.endsWith("ar") || e.endsWith("ar.exe")) {
                ret.command = e;
            }
            else if (e.endsWith(".a")) {
                ret.target = e;
            }
            else if (e.endsWith(".o")) {
                ret.inputs.push(e);
            }
            else if (e == "qc") {
            }
            else {
                Logger.err(cmd + "\nar未解析参数 " + e);
                process.exit();
            }
        }
        Logger.info("---ar----" + ret.workDir + "\n\t" + ret.isLink + "," + ret.target);
        return ret;
    }

    static clangxxCheck1(e) {
        let ss = ["--sysroot=",
            "-pthread",
            "-Qunused-arguments",
            "-ffunction-sections",
            "-fdata-sections",
            "-fvisibility=hidden",
            "-fvisibility-inlines-hidden",
            "-funwind-tables",
            "-fwrapv",
            "-O3",
            "-fPIC",
            "-shared",
            "-ldl",
            "-lm",
            "-lpthread",
            "-lrt",
            "-fPIE",
            "-g",
            "-ftemplate-depth=1024",
            "-pedantic-errors"
        ];
        for (let s of ss) {
            if (e.startsWith(s)) {
                return true;
            }
        }
        if (e == "-w") {//-----直接忽略的编译参数(和链接参数)
            return true;
        }
        return false;
    }
    static clangxxCheck2(local, e) {
        if (e.startsWith("-isystem")) {//需要 不清楚这个有什么用
            if (e == "-isystem") {//-isystem xxxx
                local.ret.includes.push(local.eles[local.p++]);
            }
            else {//-Ixxx
                local.ret.includes.push(e.substring(2));
            }
            return true;
        }
        return false;
    }
    static clangxxCheck3(local, e) {
        if (e.startsWith("-D")) {//需要记录到defines里面的参数
            //需要 是否-D开头的，全部记录到defines里面
            if (e.length == 2) {//-D xxx
                local.ret.defines.push(local.eles[local.p++]);
            }
            else {//-Dxxx
                local.ret.defines.push(e.substring(2));
            }
            return true;
        }
        return false;
    }
    static clangxxCheck4(local, e) {
        if (e.startsWith("-I")) {//需要记录到includes的参数
            if (e.length == 2) {//-I xxx
                local.ret.includes.push(local.eles[local.p++]);
            }
            else {//-Ixxx
                local.ret.includes.push(e.substring(2));
            }
            return true;
        }
        return false;
    }
    static clangxxCheck5(local, e) {
        if (this.validCFlag(e, Tool.getAllowedCxx().compileflag)) {
            local.ret.cflags.push(e); //需要记录到flags里面的参数
            return true;
        }
        return false;
    }
    static clangxxCheck6(local, e) {
        if (e.startsWith("-Xclang")) {//透传参数
            let v = local.eles[local.p++];
            if (v != "-emit-pch") {//需要丢弃这个选项
                local.ret.cflags.push(e);
                local.ret.cflags.push(v);
            }
            return true;
        }
        return false;
    }
    static clangxxCheck7(local, e) {
        if (e.startsWith("-W")) {//需要 -W开头的怎么处理,-W -Wall -Werror=return-type -Wno-unnamed-type-template-args
            if (e.startsWith("-Wno-")) {
                local.ret.cflags.push(e);
            }
            return true;
        }
        return false;
    }
    static clangxxCheck8(local, e) {
        if (e == "-o") {
            if (e.length == 2) {//-o xxx
                local.ret.target = local.eles[local.p++];
            }
            else {//-oxxx
                local.ret.target = e.substring(2);
            }
            if (local.ret.target.endsWith(".a") ||
                local.ret.target.endsWith(".so") ||
                (!e.endsWith(".c") && !e.endsWith(".o"))) {
                local.ret.isLink = true;
            }
            return true;
        }
        return false;
    }
    static validSuffix(filePath, allowedSuffix) {
        for (let i = 0; i < allowedSuffix.length; ++i) {
            if (filePath.endsWith(allowedSuffix[i])) {
                return true;
            }
        }
        if (filePath.search(/\.so[\d\.]*$/) > 0) {
            return true;
        }
        return false;
    }
    static clangxxCheck9(local, e) {
        if (this.validSuffix(e, Tool.getAllowedCxx().fileSuffix) || (e.indexOf(".so.") > 0)) {
            local.ret.inputs.push(e);
            return true;
        }
        if (e.endsWith(".rsp")) {
            console.log(Tool.CURRENT_DIR);
            let rspth = path.join(Tool.CURRENT_DIR, e.substring(1));
            let data = fs.readFileSync(rspth, { encoding: "utf8" });
            if (data.endsWith("\r\n")) {
                data = data.substring(0, data.length - 2);
            }
            let datas = data.split(" ");
            let pp = [".c",
                ".o",
                '.o"',
                ".a",
                ".S",
                ".so"
            ];
            for (let d of datas) {
                for (let p of pp) {
                    if (d.endsWith(p)) {
                        local.ret.inputs.push(d);
                    }
                }
            }
            return true;
        }
        return false;
    }
    static analyzeCcClangxx(cmd) {
        if (cmd.indexOf("\"")) {
            cmd = cmd.replace(/\"/g, "");
        }
        let local = {
            ret: AnalyzeCommand.resultTemplete(),
            eles: AnalyzeCommand.splitString(cmd),
            p: 0,
        }
        while (local.p < local.eles.length) {
            let e = local.eles[local.p++];
            if (e.endsWith("clang++") || e.endsWith("clang++.exe")) {
                local.ret.command = e;
            }
            else if (AnalyzeCommand.clangxxCheck1(e)) { }
            else if (e.startsWith("-fno-rtti")) {
                local.ret.cflags.splice(local.ret.cflags.indexOf("-frtti"), 1);
            }
            else if (e.startsWith("-fno-exceptions")) {
                local.ret.cflags.splice(local.ret.cflags.indexOf("-fexceptions"), 1);
            }
            else if (AnalyzeCommand.clangxxCheck2(local, e)) { }
            else if (AnalyzeCommand.clangxxCheck3(local, e)) { }
            else if (AnalyzeCommand.clangxxCheck4(local, e)) { }
            else if (AnalyzeCommand.clangxxCheck5(local, e)) { }
            else if (AnalyzeCommand.clangxxCheck6(local, e)) { }
            else if (e.startsWith("-std=")) {
                local.ret.cflagsCc.push(e);
            }
            else if (AnalyzeCommand.clangxxCheck7(local, e)) { }
            else if (AnalyzeCommand.clangxxCheck8(local, e)) { }
            else if (e == "-c") {//编译
                local.ret.isLink = false;
            }
            else if (AnalyzeCommand.clangxxCheck9(local, e)) { }
            else {
                Logger.err(cmd + "\nclang++未解析参数 " + e);
                process.exit();
            }
        }
        Logger.info("---clang++----" + local.ret.workDir + "\n\t" + local.ret.isLink + "," + local.ret.target)
        return local.ret;
    }

    static analyzeCompileCommand(cmd) {
        //整理命令行
        while (cmd.indexOf("\\\n") >= 0) {//去除\换行
            cmd = cmd.replace("\\\n", "");
        }
        while (cmd.indexOf("\t") >= 0) {//所有tab换成空格
            cmd = cmd.replace("\t", " ");
        }
        while (cmd.endsWith("\n") || cmd.endsWith(" ")) {
            cmd = cmd.substring(0, cmd.length - 1);
        }
        let ret = null;
        switch (AnalyzeCommand.getCompileCmdId(cmd)) {
            case AnalyzeCommand.COMPILE_CMDS["clang"]:
                ret = AnalyzeCommand.analyzeCcClang(cmd);
                break;
            case AnalyzeCommand.COMPILE_CMDS["ar"]:
                ret = AnalyzeCommand.analyzeCcAr(cmd);
                break;
            case AnalyzeCommand.COMPILE_CMDS["clang++"]:
                ret = AnalyzeCommand.analyzeCcClangxx(cmd);
                break;
        }
        if (ret) {
            AnalyzeCommand.mockTarget(ret);//解析出的目标，touch一个出来，否则会出现不同Makefile中依赖无法找到的问题
            return ret;
        }
        Logger.err("解析编译命令行失败:" + cmd);
        return false;
    }
}
module.exports = {
    AnalyzeCommand
}