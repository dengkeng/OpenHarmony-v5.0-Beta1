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
const { TypeList, getArrayType, getArrayTypeTwo, getMapType, EnumList, jsType2CType } 
    = require("../tools/common");
const { NapiLog } = require("../tools/NapiLog");
const { addUniqObj2List } = require("../tools/tool");
const re = require("../tools/re");

function getHDefineOfType(data, name, type, variable, inNamespace, nameSpaceName, toolNamespace) {
  if (typeof(type) === 'object') {
      // 字符常量转化
      let result = generateTypeEnum(name, data, inNamespace, nameSpaceName, toolNamespace)
      variable.hDefine += result.implH
      variable.cppDefine += result.implCpp
      variable.middleInitDefine += result.midInitEnum
      variable.midInitEnumDefine += result.midInitEnumDefine
  } else  if (type.indexOf("|") >= 0) {
    variable.hDefine += "\n   typedef std::any %s;".format(name)
  } else if (type == "string") {
    variable.hDefine += "\n   typedef std::string %s;".format(name)
  }
  else if (type == "boolean") {
      variable.hDefine += "\n   typedef bool %s;".format(name)
  } 
  else if (type.substring(0, 12) == "NUMBER_TYPE_") {
      variable.hDefine += "\n   typedef %s %s;".format(type, name)
  } 
  else {
      NapiLog.logError(`
      ---- generateVariable fail %s,%s ----
      `.format(name, type));
  }
}

function generateTypeEnum(name, data, inNamespace, nameSpaceName, toolNamespace) {
  let implH = ""
  let implCpp = ""
  let midInitEnum = ""
  let midInitEnumDefine = ""

  implH = `\nclass %s {\npublic:\n`.format(name, implH)
  for (let i in data.element) {
      let v = data.element[i]
      if(midInitEnumDefine == "") {                
        midInitEnumDefine += 'std::map<const char *, std::any> enumMap%s;\n'.format(name)
      }
      implH += `    static const std::string %s;\n`.format(v.name)
      implCpp += `\nconst std::string %s::%s = "%s";\n`.format(name, v.name, v.value)
      midInitEnum += '    %s%s::%senumMap%s["%s"] = "%s";\n'.format(inNamespace, nameSpaceName, toolNamespace, name, v.name, v.value)
  }
  midInitEnum += '    pxt->CreateEnumObject("%s", %s%s::%senumMap%s);\n'.format(name, inNamespace, nameSpaceName, toolNamespace, name)
  implH += `};\n`
  let result = {
      implH: implH,
      implCpp: implCpp,
      midInitEnum: midInitEnum,
      midInitEnumDefine: midInitEnumDefine
  }
  return result
}

function getHDefineOfVariable(name, type, variable, optional) {
    if (type.indexOf("|") >= 0) {
        unionTypeString(name, type, variable, optional)
    } else if (type == "string") {
        if (optional) {
            variable.hDefine += "\n    std::optional<std::string> %s;".format(name)
        } else {
            variable.hDefine += "\n    std::string %s;".format(name)
        }
    }
    else if (TypeList.getValue(type)) variable.hDefine += "\n    %s %s;".format(type, name)
    else if (EnumList.getValue(type)) variable.hDefine += "\n    %s %s;".format(type, name)
    else if (type.indexOf("Array<") == 0) {
        typeArrFunctionOne(type, variable, name, optional);
    } else if (type == "boolean") {
        if (optional) {
            variable.hDefine += "\n    std::optional<bool> %s;".format(name)
        } else {
            variable.hDefine += "\n    bool %s;".format(name)
        }
    } else if (type.substring(type.length - 2) == "[]") {
        typeArrFunctionTwo(type, variable, name, optional);
    } else if (type.substring(0, 4) == "Map<" || type.indexOf("{[key:") == 0) {
        variable.hDefine += mapTypeString(type, name, optional)
    } else if (type == "any") {
        variable.hDefine += anyTypeString(type, name)
    } else if (type.substring(0, 12) == "NUMBER_TYPE_") {
        if (optional) {
            variable.hDefine += "\n    std::optional<%s> %s;".format(type, name)
        } else {
            variable.hDefine += "\n    %s %s;".format(type, name)
        }
    } else if (type == "Object" || type == "object") {
        variable.hDefine += "\n    std::map<std::string, std::any> %s;".format(name)
    }
    else {
        NapiLog.logError(`
        ---- generateVariable fail %s,%s ----
        `.format(name, type));
    }
}

function typeArrFunctionTwo(type, variable, name, optional) {
    let arrayType = getArrayTypeTwo(type);
    if (arrayType == "any") {
        variable.hDefine += "\n    std::string %s_type;\n    std::any %s;".format(name, name);
    } else {
        let cType = jsType2CType(arrayType);
        if (optional) {
            variable.hDefine += "\n    std::optional<std::vector<%s>> %s;".format(cType, name);
        } else {
            variable.hDefine += "\n    std::vector<%s> %s;".format(cType, name);
        }
    }
}

function typeArrFunctionOne(type, variable, name, optional) {
    let arrayType = getArrayType(type);
    if (arrayType == "any") {
        variable.hDefine += "\n    std::string %s_type; \n    std::any %s;".format(name, name);
    } else {
        let cType = jsType2CType(arrayType);
        if (optional) {
            variable.hDefine += "\n    std::optional<std::vector<%s>> %s;".format(cType, name);
        } else {
            variable.hDefine += "\n    std::vector<%s> %s;".format(cType, name);
        }
    }
}

function generateVariable(value, variable) {
    let name = value.name
    let type = value.type
    let optional = value.optional
    getHDefineOfVariable(name, type, variable, optional)
}

function unionTypeString(name, type, variable, optional) {
    if (optional) {
        variable.hDefine += `std::optional<std::string> %s_type;\n
        std::optional<std::any> %s;`.format(name, name)
    } else {
        variable.hDefine += `std::string %s_type;\n
        std::any %s;`.format(name, name)
    }
    
}

function mapTypeString(type, name, optional) {
    let mapType = getMapType(type)
    let mapTypeString
    if (mapType[1] != undefined && mapType[2] == undefined) {
        if (mapType[1] == "string") mapTypeString = "std::string, std::string"
        else if (mapType[1] == "boolean") mapTypeString = "std::string, bool"
        else if (mapType[1].substring(0, 12) == "NUMBER_TYPE_") {
            mapTypeString = "std::string, %s".format(mapType[1])
        }
        else if (mapType[1].substring(0, 12) == "any") {
            mapTypeString = `std::string, std::any`.format(mapType[1])
            return `\n    std::map<%s> %s;
            std::string %s_type;`.format(mapTypeString, name, name)
        }
        else if (TypeList.getValue(mapType[1])) mapTypeString = "std::string, %s".format(mapType[1])
    }
    if (mapType[2] != undefined) {
        if (mapType[2] == "string") mapTypeString = "std::string, std::map<std::string, std::string>"
        else if (mapType[2] == "boolean") mapTypeString = "std::string, std::map<std::string, bool>"
        else if (mapType[2].substring(0, 12) == "NUMBER_TYPE_") {
            mapTypeString = "std::string, std::map<std::string, %s>".format(mapType[2])
        }
    }
    if (mapType[3] != undefined) {
        if (mapType[3] == "string") mapTypeString = "std::string, std::vector<std::string>"
        else if (mapType[3] == "boolean") mapTypeString = "std::string, std::vector<bool>"
        else if (mapType[3].substring(0, 12) == "NUMBER_TYPE_") {
            mapTypeString = "std::string, std::vector<%s>".format(mapType[3])
        }
    }
    if (optional) {
        return "\n    std::optional<std::map<%s>> %s;".format(mapTypeString, name);
    } else {
        return "\n    std::map<%s> %s;".format(mapTypeString, name);
    }
}

function anyTypeString (type, name) {
    let anyType = `\n    std::string %s_type;
    std::any %s;`

    return anyType.format(name, name)
}
function getSelfNs(inNamespace) {
    let selfNs = ''
    if (inNamespace.length > 0) {
        let nsl = inNamespace.split("::")
        nsl.pop()
        if (nsl.length >= 2) {
            selfNs = ", " + nsl[nsl.length - 1]
        }
    }
    return selfNs    
}

function generateType(name, data, inNamespace, inNameSpaceEnum, nameSpaceName, toolNamespace) {
    let result = {
      implH: '',
      implCpp: '',
      middleBody: '',
      middleInit: '',
      declarationH:'',
      middleH: '',
      midInitEnumDefine: ''
    }
    let resultConnect = connectResult(name, data, inNameSpaceEnum, nameSpaceName, toolNamespace)
    let implH = resultConnect[1]
    let implCpp = resultConnect[2]
    let middleInit = resultConnect[3]
    let midInitEnumDefine = resultConnect[4]
    let selfNs = ""
    selfNs = getSelfNs(inNamespace);
    if (implH.indexOf("typedef") > 0) {
      result = {
        implH: implH,
        implCpp: implCpp,
        middleBody: '',
        middleInit: middleInit,
        declarationH:'',
        middleH: '',
        midInitEnumDefine: midInitEnumDefine
      }
    } else if (implCpp !== '' && middleInit !== '') {
      result = {
        implH: implH,
        implCpp: implCpp,
        middleBody: '',
        middleInit: middleInit,
        declarationH:'',
        middleH: '',
        midInitEnumDefine: midInitEnumDefine
      }
    } else {
      result = {
        implH: `
  struct %s {
    %s
  };\n`.format(name, implH),
        implCpp: implCpp,
        middleBody: '',
        middleInit: middleInit,
        declarationH: `
        struct %s;\r`.format(name),
        middleH: '',
        midInitEnumDefine: ''
      }
    }
    return result
}

// 递归获取所有成员属性和
function getAllPropties(interfaceBody, properties) {
    for (let i in interfaceBody.value) {
        addUniqObj2List(interfaceBody.value[i], properties.values)
    }
} 

function connectResult(name, data, inNamespace, nameSpaceName, toolNamespace) {
    let implH = ""
    let implCpp = ""
    let middleFunc = ""
    let middleInit = ""
    let midInitEnumDefine = ""
    let variable = {
        hDefine: "",
        cppDefine: "",
        middleInitDefine: "",
        midInitEnumDefine: ""
    }
    if (Object.prototype.hasOwnProperty.call(data, "value")) {
      data.allProperties = {values:[]}
      getAllPropties(data, data.allProperties)
      for (let i in data.allProperties.values) {
          let v = data.allProperties.values[i]
          generateVariable(v, variable)
      }
    } else {
      let type = data
      getHDefineOfType(data, name, type, variable, inNamespace, nameSpaceName, toolNamespace)
    }
    implH += variable.hDefine
    implCpp += variable.cppDefine
    middleInit += variable.middleInitDefine
    midInitEnumDefine += variable.midInitEnumDefine
    return [middleFunc, implH, implCpp, middleInit, midInitEnumDefine]
}

module.exports = {
    generateType,
    connectResult,
    generateVariable,
    mapTypeString,
    generateTypeEnum
}


