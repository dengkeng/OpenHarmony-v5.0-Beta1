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
// remote消息中变量类型名(key)与对应的写parcel方法名(value)的映射（参考parcel.h）
const DATA_W_MAP = new Map(
    [["bool", "WriteBoolUnaligned"], ["int8_t", "WriteInt8"], ["uint8_t", "ReadUint8"],
     ["int16_t", "WriteInt16"], ["uint16_t", "WriteUint16"],
     ["int32_t", "WriteInt32"], ["uint32_t", "WriteUint32"], ["int64_t", "WriteInt64"], ["uint64_t", "WriteUint64"],
     ["float", "WriteFloat"], ["double", "WriteDouble"], ["char *", "WriteCString"], ["std::string", "WriteString"],
     ["string", "WriteString"]
]);

// remote消息中变量类型名(key)与对应的读parcel方法名(value)的映射（参考parcel.h）
const DATA_R_MAP = new Map(
    [["bool", "ReadBoolUnaligned"], ["int8_t", "ReadInt8"], ["uint8_t", "ReadUint8"],
     ["int16_t", "ReadInt16"], ["uint16_t", "ReadUint16"],
     ["int32_t", "ReadInt32"], ["uint32_t", "ReadUint32"], ["int64_t", "ReadInt64"], ["uint64_t", "ReadUint64"],
     ["float", "ReadFloat"], ["double", "ReadDouble"], ["char *", "ReadCString"], ["std::string", "ReadString"],
     ["string", "ReadString"]
]);

// 常用类型转换表, 将C语言常见类型(key)转换为remote data读写函数使用的类型(value)
// 例如 ErrCode 类型在框架中的系统原型为int类型，这里映射成int32_t，
// 因为int32_t类型在 DATA_W_MAP/DATA_R_MAP 表中有对应的读写数据方法(WriteInt32/ReadInt32)
const TYPE_DEF_MAP = new Map(
    [["ErrCode", "int32_t"], ["char", "int8_t"], ["short", "int16_t"], ["int", "int32_t"], ["long", "int64_t"],
    ["unsigned char", "uint8_t"], ["unsigned short", "uint16_t"], ["unsigned int", "uint32_t"], 
    ["unsigned long", "uint64_t"], ["double_t", "double"], ["float_t", "float"], ["size_t", "double"],
    ["long long", "double"], ["long double", "double"]
]);

// remote消息中vector变量类型名(key)与对应的写parcel方法名(value)的映射（参考parcel.h）
const VECTOR_W_MAP = new Map(
    [["bool", "WriteBoolVector"], ["int8_t", "WriteInt8Vector"], ["uint8_t", "WriteUInt8Vector"],
     ["int16_t", "WriteInt16Vector"], ["uint16_t", "WriteUInt16Vector"], ["int32_t", "WriteInt32Vector"], 
     ["uint32_t", "WriteUInt32Vector"], ["int64_t", "WriteInt64Vector"], ["uint64_t", "WriteUInt64Vector"],
     ["float", "WriteFloatVector"], ["double", "WriteDoubleVector"], ["u16string", "WriteString16Vector"], 
     ["std::string", "WriteStringVector"], ["string", "WriteStringVector"]
]);

// remote消息中vector变量类型名(key)与对应的读parcel方法名(value)的映射（参考parcel.h）
const VECTOR_R_MAP = new Map(
    [["bool", "ReadBoolVector"], ["int8_t", "ReadInt8Vector"], ["uint8_t", "ReadUInt8Vector"],
     ["int16_t", "ReadInt16Vector"], ["uint16_t", "ReadUInt16Vector"], ["int32_t", "ReadInt32Vector"], 
     ["uint32_t", "ReadUInt32Vector"], ["int64_t", "ReadInt64Vector"], ["uint64_t", "ReadUInt64Vector"],
     ["float", "ReadFloatVector"], ["double", "ReadDoubleVector"], ["u16string", "ReadString16Vector"],
     ["std::string", "ReadStringVector"], ["string", "ReadStringVector"]
]);

function getParcelType(srcType) {
    let parcelType = TYPE_DEF_MAP.get(srcType);
    return parcelType === undefined ? srcType : parcelType;
}

class MarshallInfo {
    constructor(className) {
        this.className = className;
        this.marshallFuncName = "";
        this.marshallFuncStr = "";
        this.unmarshallFuncName = "";
        this.unmarshallFuncStr = "";
    }
}

class AllParseFileList { }
AllParseFileList.parseFile_ = [];
AllParseFileList.push = function (ifs) {
    AllParseFileList.parseFile_.push(ifs)
}
AllParseFileList.pop = function () {
    AllParseFileList.parseFile_.pop()
}
AllParseFileList.clearAll = function () {
    AllParseFileList.parseFile_.splice(0, AllParseFileList.parseFile_.length)
}
AllParseFileList.findClassByName = function (destClassName) {
    for (let i = 0; i < AllParseFileList.parseFile_.length; ++i) {
        let classes = AllParseFileList.parseFile_[i].classes;
        for (let className in classes) {
            if (className == destClassName) {
                classes[className].isInclude = AllParseFileList.parseFile_[i].isInclude;
                return classes[className];
            }
        }
    }
    return null;
}


/**
 * 记录正在生成序列化代码的类名，防止嵌套循环
 */
class ProcessingClassList { }
ProcessingClassList.classes_ = [];
ProcessingClassList.push = function (classObj) {
    if (this.findByName(classObj.className) != null) {
        // 已存在的class不重复添加
        return;
    }
    ProcessingClassList.classes_.push(classObj)
}
ProcessingClassList.clearAll = function () {
    ProcessingClassList.classes_.splice(0, ProcessingClassList.classes_.length)
}
ProcessingClassList.findByName = function (className) {
    for (let i = 0; i < ProcessingClassList.classes_.length; ++i) {
        if (ProcessingClassList.classes_[i].className == className) {
            return ProcessingClassList.classes_[i];
        }
    }
    return null;
}

module.exports = {
    DATA_W_MAP, DATA_R_MAP, VECTOR_W_MAP, VECTOR_R_MAP, getParcelType, AllParseFileList, MarshallInfo,
    ProcessingClassList
}

