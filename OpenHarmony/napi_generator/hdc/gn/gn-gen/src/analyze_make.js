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
const childProcess = require("child_process");
const fs = require("fs")
const path = require("path");
const { AnalyzeCommand } = require("./analyze_command");
const { Logger } = require("./logger");
const { Tool } = require("./tool");

class AnalyzeMake {
    constructor() {

    }

    static USE_UDP_COLLECTOR = true;
    static collectByUdp(makeProjectPath) {
        const dgram = require("dgram");
        let udpServer_ = dgram.createSocket("udp4");
        let analyzeResult = [];
        udpServer_.bind(6000);
        udpServer_.on('listening', () => {
            Tool.pushd(makeProjectPath);
            let ret = childProcess.spawn(Tool.getMake(), ["-C", makeProjectPath, "-n"]);
            ret.stdout.on('data', (data) => {//要有，不然不进入close
            });
            ret.stderr.on('data', (data) => {
                Logger.err(data.toString());
            });
            ret.on('close', (code) => {
                if (code == 0) {
                    Logger.info("-----------------------------make ok");
                    udpServer_.close();
                    udpServer_ = null;

                    AnalyzeCommand.storeCommands();

                    Tool.generateTarget(makeProjectPath, analyzeResult);//生成结果目标
                }
                else Logger.err("make fail");
            });
        });
        udpServer_.on('error', (e) => {
            Logger.err("udp error");
        });
        udpServer_.on('message', (msg, rinfo) => {
            let acmd = msg.toString();
            let ret = AnalyzeCommand.analyze(acmd);//解析命令msg
            if (ret.length > 0) {
                analyzeResult.push(...ret);
            }
            udpServer_.send("ok", 0, 2, rinfo.port, rinfo.address);//反馈ok给make继续执行
        });
    }
    static analyzeBreakup() {
        let acmd = ""
        for (let l of dlist) {
            if (l.endsWith("\\")) { // 合并带有换行符的命令
                acmd += l;
            }
            else {
                acmd += l;
                if (acmd.length > 0) {
                    cmdlist.push(acmd);
                    let ret = AnalyzeCommand.analyze(acmd);
                    if (ret.length > 0) {
                        analyzeResult.push(...ret);
                    }
                }
                acmd = "";
            }
        }
    }
    static analyze(makeProjectFile) {
        let makeProjectPath = path.parse(makeProjectFile);
        if (!fs.existsSync(makeProjectFile)) {
            Logger.err("Makefile not exist in " + makeProjectPath.dir);
            return;
        }
        if (AnalyzeMake.USE_UDP_COLLECTOR) {
            AnalyzeMake.collectByUdp(makeProjectPath.dir);
            return;
        }
        Tool.pushd(makeProjectPath.dir);
        let ret = childProcess.spawn("make", ["-C", makeProjectPath.dir, "-n"]);
        let cmdlist = [];
        let analyzeResult = [];
        let procData = "";
        ret.stdout.on('data', (data) => {
            procData += data.toString();
            let p = procData.lastIndexOf("\n");
            if (p < 0) {
                return;
            }
            let dlist = procData.substring(0, p).split("\n");
            procData = procData.substring(p + 1);
            AnalyzeMake.analyzeBreakup(dlist, cmdlist, analyzeResult);
        });
        ret.stderr.on('data', (data) => {
            Logger.err(data.toString());
        });
        ret.on('close', (code) => {
            if (code == 0) {
                Logger.info("-----------------------------make ok");
                Tool.generateTarget(makeProjectPath.dir, analyzeResult);//生成结果目标
            }
            else Logger.err("make fail");
        });
    }
}

module.exports = {
    AnalyzeMake
}