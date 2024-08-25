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
const { writeFile } = require("../tools/FileRW");
const re = require("../tools/re");

let gypTemplete = `
{
    "targets": [
        {
          "target_name": "[implName]",
          "sources": [[businessCodeCpp]
              "./[implName].cpp",
              "./[implName]_middle.cpp",
              "./tool_utility.cpp"],
          "include_dirs": ["."],
          "cflags_cc": [ "-frtti","-std=c++17" ]
        }
    ]
}
`

/**创建nodejs编译文件，用于在ubuntu测试 */
function generateGYP(destDir, implName, license, bindingCpp) {
    let ss = gypTemplete.replaceAll("[implName]", implName)
    ss = ss.replaceAll("[businessCodeCpp]", bindingCpp)
    if (license) {
        let s2 = license.substring(2, license.length - 2).split("\n");
        license = "";
        for (let i = 1; i < s2.length; i++) {
            if (s2[i].length > 0) {
                while (s2[i][0] == " ") s2[i] = s2[i].substring(1);
                if (s2[i].length > 3 && s2[i][0] == "*") {
                    license += "#" + s2[i].substring(1) + "\n";
                }
            }
        }
    }
    writeFile(re.pathJoin(destDir, "binding.gyp"), null != license ? (license + "\n" + ss) : ss)

    writeFile(re.pathJoin(destDir, "test.sh"), "node-gyp configure build && sleep 0.5 && node --expose-gc test.js")

}

module.exports = {
    generateGYP
}