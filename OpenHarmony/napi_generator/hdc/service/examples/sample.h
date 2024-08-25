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
#ifndef EXAM_H
#define EXAM_H

#include <mutex>
#include <thread>
#include <unordered_map>
#include <string>

using std::string;

namespace OHOS {
namespace Example {
class Basic {
public:
    std::string basicName;

    int getBasicId()
    {
        return this->basicId;
    }
    void setBasicId (int id)
    {
        this->basicId = id;
    }

private:
    int basicId;
};

class Human : public Basic {
public:
    bool getOpFlag()
    {
        return this->opFlag;
    };
    void setOpFlag (bool flag)
    {
        this->opFlag = flag;
    };
    std::string getOpDesc()
    {
        return this->opDesc;
    };
    void setOpDesc(std::string desc)
    {
        this->opDesc = desc;
    };
    int getOpSeqId()
    {
        return this->opSeqId;
    };
    void setOpSeqId(int id)
    {
        opSeqId = id;
    };

    std::string opName;
    int age = 0;
private:
    bool opFlag;
    std::string opDesc;
    int opSeqId;
}

struct Book {
    int getCc()
    {
        return this->cc;
    };
    void setCc(int cc)
    {
        this->cc = cc;
    };
    Basic getBasicObj()
    {
        return this->basicObj;
    };
    void setBasicObj(Basic obj)
    {
        this->basicObj = obj;
    };
public:
    int aa;
    bool bb;
    Basic direcObj;
private:
    int cc;
    Basic basicObj;
}

/**
 * @brief service服务，提供IPC调用接口
 * @ServiceClass
 */
class Exam2 {
public:
    Book getBook(Basic& basic);
    int fun1 (Book v1);
    int fun2 (Basic& basic, Human& human);
};
}  // namespace Example
}  // namespace OHOS
#endif  // EXAM_H
