/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ROSENRENDER_ROSEN_WEBGL_RENDERING_CONTEXT
#define ROSENRENDER_ROSEN_WEBGL_RENDERING_CONTEXT

#include "webgl_rendering_context_base.h"
#include "webgl_rendering_context_overloads.h"
#include "webgl_rendering_context_base_impl.h"
#include "napi/n_exporter.h"

namespace OHOS {
namespace Rosen {
class WebGLRenderingContext : public WebGLRenderingContextBasicBase, public WebGLRenderingContextBase,
    public WebGLRenderingContextOverloads, public NExporter {
public:
    inline static const std::string className = "WebGLRenderingContext";

    bool Export(napi_env env, napi_value exports) override;

    std::string GetClassName() override;

    WebGLRenderingContext(napi_env env, napi_value exports);

    explicit WebGLRenderingContext() : WebGLRenderingContextBasicBase(), contextImpl_(0, this) {};

    virtual ~WebGLRenderingContext();

    Impl::WebGLRenderingContextBaseImpl &GetWebGLRenderingContextImpl()
    {
        return contextImpl_;
    }

    void Init() override
    {
        WebGLRenderingContextBasicBase::Init();
        contextImpl_.Init();
    }
private:
    Impl::WebGLRenderingContextBaseImpl contextImpl_;
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSENRENDER_ROSEN_WEBGL_RENDERING_CONTEXT
