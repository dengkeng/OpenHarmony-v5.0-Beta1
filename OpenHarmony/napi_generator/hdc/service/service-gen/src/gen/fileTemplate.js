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

let iServiceHTemplate = `#ifndef I_[marcoName]_SERVICE_H
#define I_[marcoName]_SERVICE_H

[includes]
#include "iremote_broker.h"
#include "iremote_proxy.h"
[using]

namespace OHOS {
namespace [serviceName] {
[dependClasses]
class I[className]Service : public OHOS::IRemoteBroker {
public:
    enum {
        [funcEnum]
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.[serviceName].I[className]Service");
public:
    [functions]
};
[marshallFunctions]
} // namespace [serviceName]
} // namespace OHOS
#endif // I_[marcoName]_SERVICE_H
`;
let proxyHTemplate = `#ifndef [marcoName]_PROXY_H
#define [marcoName]_PROXY_H
#include "message_parcel.h"
#include "parcel.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "[iServiceHInclude]"

namespace OHOS {
namespace [serviceName] {
class [className]Proxy : public IRemoteProxy<I[className]Service> {
public:
    explicit [className]Proxy(const sptr<IRemoteObject> &impl);
    ~[className]Proxy() = default;
    [functions]
private:
    static inline BrokerDelegator<[className]Proxy> delegator_;
};

class [className]DeathRecipient : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    [className]DeathRecipient();
    virtual ~[className]DeathRecipient();
};
} // namespace [serviceName]
} // namespace OHOS
#endif // [marcoName]_PROXY_H
`;

let stubHTemplate = `#ifndef [marcoName]_STUB_H
#define [marcoName]_STUB_H
#include "iremote_stub.h"
#include "message_parcel.h"
#include "parcel.h"
#include "[iServiceHInclude]"

namespace OHOS {
namespace [serviceName] {
class [className]Stub : public IRemoteStub<I[className]Service> {
public:
    [className]Stub();
    virtual ~[className]Stub();
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption &option) override;
private:
    using [className]InnerFunc = ErrCode ([className]Stub::*)(MessageParcel &data, MessageParcel &reply);
    [innerFuncDef]
    std::unordered_map<uint32_t, [className]InnerFunc> innerFuncs_;
};
} // namespace [serviceName]
} // namespace OHOS
#endif // [marcoName]_STUB_H`;

let serviceHTemplate = `#ifndef [marcoName]_SERVICE_H
#define [marcoName]_SERVICE_H
#include "ipc_skeleton.h"
#include "system_ability.h"
#include "[stubHInclude]"

namespace OHOS {
namespace [serviceName] {
// Business implementation
class [className]Service : public SystemAbility, public [className]Stub {
public:
    DECLARE_SYSTEM_ABILITY([className]Service);
    DISALLOW_COPY_AND_MOVE([className]Service);
    explicit [className]Service(int32_t systemAbilityId, bool runOnCreate = true);
    ~[className]Service() override;

    // Business implementation
    [functions]

    // implement SystemAbility methods
    void OnStart() override;
    void OnStop() override;
};
}
}
#endif // [marcoName]_SERVICE_H`;

let proxyCppTemplate = `#include "[proxyHInclude]"
using namespace std;

namespace OHOS {
namespace [serviceName] {
[className]Proxy::[className]Proxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<I[className]Service>(impl){}

[remoteFuncImpl]
/**
 * @brief Notify that a remote object died.
 * It's called when the linked remote object died.
 * 
 * @param remote The died IRemoteObject handler of the remote object 
 */
void [className]DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{

}

[className]DeathRecipient::[className]DeathRecipient()
{
}

[className]DeathRecipient::~[className]DeathRecipient()
{
}

} // namespace [serviceName]
} // namespace OHOS
`;
let proxyFuncTemplate = `[retType] [className]Proxy::[funcName]([params])
{
    int retCode;
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    [writeData]
    retCode = Remote()->SendRequest([funcEnum], data, reply, option);
    retCode = reply.ReadInt32();
    if (retCode != ERR_OK) {

    }

    [readReply]
}\n\n`;

let stubCppTemplate = `#include "[stubHInclude]"
using namespace std;

namespace OHOS {
namespace [serviceName] {

[className]Stub::[className]Stub()
{
    [innerFuncMap]
}

[className]Stub::~[className]Stub()
{
    innerFuncs_.clear();
}

int [className]Stub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    std::u16string descriptor = [className]Stub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        return OBJECT_NULL;
    }
    auto itFunc = innerFuncs_.find(code);
    if (itFunc != innerFuncs_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

[innerFuncImpl]

} // namespace [serviceName]
} // namespace OHOS
`;

let stubInnerFuncTemplate = `ErrCode [className]Stub::[funcName]Inner(MessageParcel &data, MessageParcel &reply)
{
    int retCode = ERR_OK;
    [readData]
    [writeReply]
    return retCode;
}
`;

let serviceCppTemplate = `#include "[serviceHInclude]"
#include "system_ability_definition.h"
using namespace std;

namespace OHOS {
namespace [serviceName] {
// [marcoName]_SERVICE_ID should be defined in system_ability_definition.h
REGISTER_SYSTEM_ABILITY_BY_ID([className]Service, [marcoName]_SERVICE_ID, true)

[className]Service::[className]Service(int32_t systemAbilityId, bool runOnCreate)
    :SystemAbility(systemAbilityId, runOnCreate)
{

}

[className]Service::~[className]Service(){

}

void [className]Service::OnStart()
{
    // Publish(): Register service by method ISystemAbilityManager->AddSystemAbility()
    bool isPublished = Publish(this);
    if (!isPublished) {
        // Log: Failed to publish the service
    }
    return;
}

void [className]Service::OnStop()
{

}

[serviceFuncImpl]
}
}`;

let serviceFuncImplTemplate = `[retType] [className]Service::[funcName]([params])
{
    [retType] ret;
    // TODO: Invoke the business implementation
    return ret;
}
`;
let clientCppTemplate = `#include "[proxyHInclude]"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::[serviceName];

sptr<I[className]Service> getRemoteProxy()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        return nullptr;
    }

    // [marcoName]_SERVICE_ID should be defined in system_ability_definition.h
    sptr<IRemoteObject> object = saMgr->GetSystemAbility([marcoName]_SERVICE_ID);
    sptr<I[className]Service> proxy = nullptr;
    if (object != nullptr) {
        sptr<IRemoteObject::DeathRecipient> death(new [className]DeathRecipient());
        object->AddDeathRecipient(death.GetRefPtr());
        proxy = iface_cast<I[className]Service>(object);
    }

    if (proxy == nullptr) {
        return nullptr;
    }

    return proxy;
}

int main(int argc, char *argv[])
{
    auto proxy = getRemoteProxy();
    // TODO: Invoke remote method by proxy
    [clientFuncInvoke]

    IPCSkeleton::JoinWorkThread();
    return 0;
}`;

let buildGnTemplate = `import("//build/ohos.gni")

ohos_shared_library("[lowServiceName]service") {
  sources = [
    "//[lowServiceName]service/src/[iServiceCppFile]",
    "//[lowServiceName]service/src/[stubCppFile]",
    "//[lowServiceName]service/src/[serviceCppFile]"
  ]
  include_dirs = [
    "//[lowServiceName]service/include",
    "//[lowServiceName]service/interface",
    "//utils/native/base/include"
  ]

  deps = [
    "//base/startup/syspara_lite/interfaces/innerkits/native/syspara:syspara",
    "//utils/native/base:utils",
  ]

  external_deps = [
    "hiviewdfx_hilog_native:libhilog",
    "ipc:ipc_core",
    "safwk:system_ability_fwk",
    "samgr_standard:samgr_proxy",
    "startup_l2:syspara",
  ]

  part_name = "[lowServiceName]service_part"
  subsystem_name = "[lowServiceName]service"
}

ohos_executable("[lowServiceName]client") {
    sources = [
    "//[lowServiceName]service/src/[iServiceCppFile]",
    "//[lowServiceName]service/src/[proxyCppFile]",
    "//[lowServiceName]service/src/[clientCppFile]"
  ]

  include_dirs = [
    "//[lowServiceName]service/include",
    "//[lowServiceName]service/interface",
    "//utils/native/base/include"
  ]

  deps = [
    "//utils/native/base:utils",
  ]

  external_deps = [
    "hiviewdfx_hilog_native:libhilog",
    "ipc:ipc_core",
    "samgr_standard:samgr_proxy",
  ]

  part_name = "[lowServiceName]service_part"
  subsystem_name = "[lowServiceName]service"
}
`;

let bundleJsonTemplate = `{
    "name": "@ohos/[lowServiceName]service",
    "description": "system ability framework test",
    "homePage": "https://gitee.com/",
    "version": "3.1",
    "license": "Apache License 2.0",
    "repository": "",
    "publishAs": "code-segment",
    "segment": {
        "destPath": "[lowServiceName]service"
    },
    "dirs": {},
    "scripts": {},
    "component": {
        "name": "[lowServiceName]service_part",
        "subsystem": "[lowServiceName]service",
        "adapted_system_type": [
            "standard"
        ],
        "rom": "2048KB",
        "ram": "~4096KB",
        "deps": {
            "components": [
                "hiviewdfx_hilog_native",
                "ipc",
                "samgr_standard",
                "utils_base",
                "safwk",
                "startup_l2"
            ],
            "third_party": [ "libxml2" ]
        },
        "build": {
            "sub_component": [
                "//[lowServiceName]service:[lowServiceName]service",
                "//[lowServiceName]service/sa_profile:[lowServiceName]service_sa_profile",
                "//[lowServiceName]service:[lowServiceName]client",
                "//[lowServiceName]service/etc:[lowServiceName]_service_init"
            ],
            "inner_kits": [
            ],
            "test": [
            ]
        }
    }
}`;

let profileGnTemplate = `import("//build/ohos.gni")
import("//build/ohos/sa_profile/sa_profile.gni")

ohos_sa_profile("[lowServiceName]service_sa_profile") {
  sources = [ "[serviceId].xml" ]

  part_name = "[lowServiceName]service_part"
}
`;

let profileXmlTemplate = `<?xml version="1.0" encoding="utf-8"?>
<info>
    <process>[lowServiceName]service_sa</process>
    <systemability>
        <name>[serviceId]</name>
        <libpath>lib[lowServiceName]service.z.so</libpath>
        <run-on-create>true</run-on-create>
        <distributed>false</distributed>
        <dump-level>1</dump-level>
    </systemability>
</info>
`;

let serviceCfgTemplate = `{
    "services" : [{
            "name" : "[lowServiceName]service",
            "path" : ["/system/bin/sa_main", "/system/profile/[lowServiceName]service_sa.xml"],
            "uid" : "system",
            "gid" : ["system", "shell"]
        }
    ]
}
`;

let serviceCfgGnTemplate = `import("//build/ohos.gni")

ohos_prebuilt_etc("[lowServiceName]_service_init") {
  source = "[lowServiceName]_service.cfg"
  relative_install_dir = "init"
  part_name = "[lowServiceName]service_part"
  subsystem_name = "[lowServiceName]service"
}
`;

let iServiceCppTemplate = `#include "[iServiceHInclude]"
`;

module.exports = {
    iServiceHTemplate,
    proxyHTemplate,
    stubHTemplate,
    serviceHTemplate,
    proxyCppTemplate,
    proxyFuncTemplate,
    stubCppTemplate,
    stubInnerFuncTemplate,
    serviceCppTemplate,
    serviceFuncImplTemplate,
    clientCppTemplate,
    buildGnTemplate,
    bundleJsonTemplate,
    profileGnTemplate,
    profileXmlTemplate,
    serviceCfgTemplate,
    serviceCfgGnTemplate,
    iServiceCppTemplate
}