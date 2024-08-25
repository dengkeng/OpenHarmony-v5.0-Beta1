/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "egl_core.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <EGL/eglplatform.h>
#include <GLES3/gl3.h>
#include <cmath>
#include <cstdio>
#include <hilog/log.h>

#include "../common/common.h"
#include "plugin_render.h"

namespace NativeXComponentSample {
namespace {
    constexpr int32_t NUM_9 = 9;
    constexpr int32_t NUM_8 = 8;
    constexpr int32_t NUM_7 = 7;
    constexpr int32_t NUM_6 = 6;
    constexpr int32_t NUM_5 = 5;
    constexpr int32_t NUM_4 = 4;
    constexpr int32_t NUM_3 = 3;
    constexpr int32_t NUM_2 = 2;
    constexpr int32_t NUM_1 = 1;
    constexpr int32_t NUM_1024 = 1024;
    constexpr int32_t NUM_180 = 180;
    constexpr int32_t NUM_72 = 72;
    constexpr int32_t NUM_54 = 54;
    constexpr int32_t NUM_18 = 18;
    /**
     * Vertex shader.
     */
    const char EGLDRAW_VERTEX_SHADER[] = "#version 300 es\n"
                                         "layout(location = 0) in vec4 a_position;\n"
                                         "layout(location = 1) in vec4 a_color;   \n"
                                         "out vec4 v_color;                       \n"
                                         "void main()                             \n"
                                         "{                                       \n"
                                         "   gl_Position = a_position;            \n"
                                         "   v_color = a_color;                   \n"
                                         "}                                       \n";

    /**
     * Fragment shader.
     */
    const char EGLDRAW_FRAGMENT_SHADER[] = "#version 300 es\n"
                                           "precision mediump float;                  \n"
                                           "in vec4 v_color;                          \n"
                                           "out vec4 fragColor;                       \n"
                                           "void main()                               \n"
                                           "{                                         \n"
                                           "   fragColor = v_color;                   \n"
                                           "}                                         \n";

    /**
     * Texture Render Vertex shader.
     */
    const char EGLTR_VERTEX_SHADER[] = "#version 300 es\n"
                                       "layout (location = 0) in vec3 aPos;                  \n"
                                       "layout (location = 1) in vec3 aColor;                \n"
                                       "layout (location = 2) in vec2 aTexCoord;             \n"
                                       "out vec3 ourColor;                                     \n"
                                       "out vec2 TexCoord;                                     \n"
                                       "void main()                                            \n"
                                       "{                                                      \n"
                                       "    gl_Position = vec4(aPos, 1.0);                     \n"
                                       "    ourColor = aColor;                                 \n"
                                       "    TexCoord = vec2(aTexCoord.x, aTexCoord.y);         \n"
                                       "}                                                      \n";

    /**
     * Texture Render Fragment shader.
     */
    const char EGLTR_FRAGMENT_SHADER[] = "#version 300 es   \n"
                                         "precision mediump float;                           \n"
                                         "in vec3 ourColor;                                  \n"
                                         "in vec2 TexCoord;                                  \n"
                                         "uniform lowp sampler2D texture1;                   \n"
                                         "out vec4 FragColor;                                \n"
                                         "void main()                                        \n"
                                         "{                                                  \n"
                                         "    FragColor = texture(texture1, TexCoord);       \n"
                                         "}                                                \n";

    /**
     * Background color #801dae 青莲.
     */
    const GLfloat QL_BACKGROUND_COLOR[] = {128.0f / 255, 29.0f / 255, 174.0f / 255, 1.0f};

    /**
     * Background color #f20c00 石榴红.
     */
    const GLfloat SLH_BACKGROUND_COLOR[] = {242.0f / 255, 12.0f / 255, 00.0f / 255, 1.0f};

    /**
     * Background color #f20c00 花青.
     */
    const GLfloat HQ_BACKGROUND_COLOR[] = {00.0f / 255, 52.0f / 255, 114.0f / 255, 1.0f};

    /**
     * Draw color #7E8FFB.
     */
    const GLfloat DRAW_COLOR[] = {126.0f / 255, 143.0f / 255, 251.0f / 255, 1.0f};

    /**
     * Draw color #a3d900.
     */
    const GLfloat CH_DRAW_COLOR[] = {126.0f / 255, 143.0f / 255, 251.0f / 255, 1.0f};

    /**
     * Draw color #057748.
     */
    const GLfloat SHL_DRAW_COLOR[] = {5.0f / 255, 119.0f / 255, 72.0f / 255, 1.0f};


    /**
     * Change color #92D6CC.
     */
    const GLfloat CHANGE_COLOR[] = {146.0f / 255, 214.0f / 255, 204.0f / 255, 1.0f};

    /**
     * Background area.
     */
    const GLfloat BACKGROUND_RECTANGLE_VERTICES[] = {-1.0f, 1.0f, 1.0f, 1.0f, 1.0f, -1.0f, -1.0f, -1.0f};

    /**
     * Get context parameter count.
     */
    const size_t GET_CONTEXT_PARAM_CNT = 1;

    /**
     * Fifty percent.
     */
    const float FIFTY_PERCENT = 0.5;

    /**
     * Pointer size.
     */
    const GLint POINTER_SIZE = 2;

    /**
     * Triangle fan size.
     */
    const GLsizei TRIANGLE_FAN_SIZE = 4;

    /**
     * Egl red size default.
     */
    const int EGL_RED_SIZE_DEFAULT = 8;

    /**
     * Egl green size default.
     */
    const int EGL_GREEN_SIZE_DEFAULT = 8;

    /**
     * Egl blue size default.
     */
    const int EGL_BLUE_SIZE_DEFAULT = 8;

    /**
     * Egl alpha size default.
     */
    const int EGL_ALPHA_SIZE_DEFAULT = 8;

    /**
     * Default x position.
     */
    const int DEFAULT_X_POSITION = 0;

    /**
     * Default y position.
     */
    const int DEFAULT_Y_POSITION = 0;

    /**
     * Gl red default.
     */
    const GLfloat GL_RED_DEFAULT = 0.0;

    /**
     * Gl green default.
     */
    const GLfloat GL_GREEN_DEFAULT = 0.0;

    /**
     * Gl blue default.
     */
    const GLfloat GL_BLUE_DEFAULT = 0.0;

    /**
     * Gl alpha default.
     */
    const GLfloat GL_ALPHA_DEFAULT = 1.0;

    /**
     * Program error.
     */
    const GLuint PROGRAM_ERROR = 0;

    /**
     * Shape vertices size.
     */
    const int SHAPE_VERTICES_SIZE = 8;

    /**
     * Position handle name.
     */
    const char POSITION_NAME[] = "a_position";

    /**
     * Position error.
     */
    const GLint POSITION_ERROR = -1;

    /**
     * Config attribute list.
     */
    const EGLint ATTRIB_LIST[] = {
        // Key,value.
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RED_SIZE, EGL_RED_SIZE_DEFAULT, EGL_GREEN_SIZE, EGL_GREEN_SIZE_DEFAULT,
        EGL_BLUE_SIZE, EGL_BLUE_SIZE_DEFAULT, EGL_ALPHA_SIZE, EGL_ALPHA_SIZE_DEFAULT, EGL_RENDERABLE_TYPE,
        EGL_OPENGL_ES2_BIT,
        // End.
        EGL_NONE};

    /**
     * Context attributes.
     */
    const EGLint CONTEXT_ATTRIBS[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
} // namespace
bool EGLCore::EglContextInit(void* window, int width, int height)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "EglContextInit execute");
    if ((window == nullptr) || (width <= 0) || (height <= 0)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "EglContextInit: param error");
        return false;
    }

    UpdateSize(width, height);
    eglWindow_ = static_cast<EGLNativeWindowType>(window);

    // Init display.
    eglDisplay_ = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglGetDisplay: unable to get EGL display");
        return false;
    }

    EGLint majorVersion;
    EGLint minorVersion;
    if (!eglInitialize(eglDisplay_, &majorVersion, &minorVersion)) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglInitialize: unable to get initialize EGL display");
        return false;
    }

    // Select configuration.
    const EGLint maxConfigSize = 1;
    EGLint numConfigs;
    if (!eglChooseConfig(eglDisplay_, ATTRIB_LIST, &eglConfig_, maxConfigSize, &numConfigs)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglChooseConfig: unable to choose configs");
        return false;
    }

    return CreateEnvironment();
}

bool EGLCore::CreateEnvironment()
{
    // Create surface.
    if (eglWindow_ == nullptr) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglWindow_ is null");
        return false;
    }
    eglSurface_ = eglCreateWindowSurface(eglDisplay_, eglConfig_, eglWindow_, NULL);
    if (eglSurface_ == nullptr) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglCreateWindowSurface: unable to create");
        eglTerminate(eglDisplay_);
        return false;
    }
    // Create context.
    eglContext_ = eglCreateContext(eglDisplay_, eglConfig_, EGL_NO_CONTEXT, CONTEXT_ATTRIBS);
    if (eglContext_ == nullptr) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglCreateWindowSurface: unable to create");
        eglDestroySurface(eglDisplay_, eglSurface_);
        eglTerminate(eglDisplay_);
        return false;
    }

    if (!eglMakeCurrent(eglDisplay_, eglSurface_, eglSurface_, eglContext_)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "eglMakeCurrent failed");
        eglDestroyContext(eglDisplay_, eglContext_);
        eglDestroySurface(eglDisplay_, eglSurface_);
        eglTerminate(eglDisplay_);
        return false;
    }
    // Create program.
    program_ = TRCreateProgram(EGLTR_VERTEX_SHADER, EGLTR_FRAGMENT_SHADER);
    if (program_ == PROGRAM_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "CreateProgram: unable to create program");
        return false;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "CreateProgram: success!");
    return true;
}

void EGLCore::TRBackground()
{
    float vertices[] = {
        // positions          // colors           // texture coords
         0.5f,  0.5f, 0.0f,   1.0f, 0.0f, 0.0f,   1.0f, 1.0f, // top right
         0.5f, -0.5f, 0.0f,   0.0f, 1.0f, 0.0f,   1.0f, 0.0f, // bottom right
        -0.5f, -0.5f, 0.0f,   0.0f, 0.0f, 1.0f,   0.0f, 0.0f // bottom left
    };
    unsigned int indices[] = {
        0, 1, 3, // first triangle
        1, 2, 3  // second triangle
    };
    unsigned int VBO = 0;
    unsigned int VAO = 0;
    unsigned int EBO = 0;
    glGenVertexArrays(1, &VAO);
    glGenBuffers(1, &VBO);
    glGenBuffers(1, &EBO);

    glBindVertexArray(VAO);

    glBindBuffer(GL_ARRAY_BUFFER, VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(indices), indices, GL_STATIC_DRAW);

    // position attribute
    glVertexAttribPointer(0, NUM_3, GL_FLOAT, GL_FALSE, NUM_8 * sizeof(float), (void*)0);
    glEnableVertexAttribArray(0);
    // color attribute
    glVertexAttribPointer(1, NUM_3, GL_FLOAT, GL_FALSE, NUM_8 * sizeof(float), (void*)(NUM_3 * sizeof(float)));
    glEnableVertexAttribArray(1);
    // texture coord attribute
    glVertexAttribPointer(NUM_2, NUM_2, GL_FLOAT, GL_FALSE, NUM_8 * sizeof(float), (void*)(NUM_6 * sizeof(float)));
    glEnableVertexAttribArray(NUM_2);
    
    // load and create a texture
    // -------------------------
    unsigned int texture;
    glGenTextures(1, &texture);
    // all upcoming GL_TEXTURE_2D operations now have effect on this texture object
    glBindTexture(GL_TEXTURE_2D, texture);
    // set the texture wrapping parameters
    // set texture wrapping to GL_CLAMP_TO_EDGE (default wrapping method)
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    // set texture filtering parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    // load image, create texture and generate mipmaps

    glClearColor(0.2f, 0.3f, 0.3f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    glBindTexture(GL_TEXTURE_2D, texture);

    glUseProgram(program_);

    glBindVertexArray(VAO);
    glDrawElements(GL_TRIANGLES, NUM_6, GL_UNSIGNED_INT, 0);

    eglSwapBuffers(eglDisplay_, eglSurface_);
}

void EGLCore::Background()
{
    GLint position = PrepareDraw();
    if (position == POSITION_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Background get position failed");
        return;
    }

    if (!ExecuteDrawBG(position, SLH_BACKGROUND_COLOR,
        BACKGROUND_RECTANGLE_VERTICES, sizeof(BACKGROUND_RECTANGLE_VERTICES))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Background execute draw failed");
        return;
    }

    if (!FinishDraw()) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Background FinishDraw failed");
        return;
    }
}

GLuint EGLCore::loadTexture()
{
    uint32_t bmpWidth = 0;
    uint32_t bmpHeight = 0;
    uint32_t bmpSize = 0;
    uint8_t bmpBit = 0;
    
    //------------------------------------------------------------
    // 读文件
    FILE *file = fdopen(fd_, "r");
    if (file == NULL) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fdopen failed!");
        return false;
    }

    // 取文件
    if (fseek(file, foff_ + NUM_18, SEEK_SET) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fseek failed!");
        return false;
    }
    
    if (fread(&bmpWidth, NUM_4, NUM_1, file) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fread failed!");
    }
    
    if (fread(&bmpHeight, NUM_4, NUM_1, file) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fread failed!");
    }
    if (fread(&bmpBit, NUM_1, NUM_1, file) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fread failed!");
    }
    if (fread(&bmpBit, NUM_1, NUM_1, file) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fread failed!");
    }
    if (fread(&bmpBit, NUM_1, NUM_1, file) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fread failed!");
    }
    bmpSize = flen_ - NUM_54;

    unsigned char *bmpData = (unsigned char *)malloc(bmpSize);
    if (bmpData == NULL) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB malloc failed!");
        fclose(file);
        return false;
    }
    if (fseek(file, foff_ + NUM_54, SEEK_SET) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fseek failed!");
        return false;
    }
    size_t readCnt = fread(bmpData, bmpSize, NUM_1, file);
    if (readCnt == 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB read_cnt is 0!");
    }

    if (fclose(file) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fclose failed!");
        return false;
    }

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "bmp_width: %{public}d", bmpWidth);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "bmp_height: %{public}d", bmpHeight);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "bmp_size: %{public}d", bmpSize);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "bmp_bit: %{public}d", bmpBit);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "read_cnt: %{public}zu", readCnt);

    free(bmpData);
    return 0;
}

void EGLCore::display(GLuint texGround)
{
    // 清空颜色缓冲区
    glClear(GL_COLOR_BUFFER_BIT);

    // 使用着色器程序
    glUseProgram(program_);

    // 绑定纹理
    glBindTexture(GL_TEXTURE_2D, texGround);

    // 获取顶点坐标和纹理坐标的位置
    GLint aPositionLocation = glGetAttribLocation(program_, "aPosition");
    GLint aTexCoordLocation = glGetAttribLocation(program_, "aTexCoord");

    // 启用顶点属性数组
    glEnableVertexAttribArray(aPositionLocation);
    glEnableVertexAttribArray(aTexCoordLocation);

    // 设置顶点属性指针
    glVertexAttribPointer(aPositionLocation, NUM_3, GL_FLOAT, GL_FALSE, 0, BACKGROUND_RECTANGLE_VERTICES);
    glVertexAttribPointer(aTexCoordLocation, NUM_2, GL_FLOAT, GL_FALSE, 0, BACKGROUND_RECTANGLE_VERTICES);

    // 绘制矩形
    glDrawArrays(GL_TRIANGLES, 0, NUM_6);

    // 禁用顶点属性数组
    glDisableVertexAttribArray(aPositionLocation);
    glDisableVertexAttribArray(aTexCoordLocation);
    
    eglSwapBuffers(eglDisplay_, eglSurface_);
}

void EGLCore::DrawBmp(uint32_t fd, uint32_t foff, uint32_t flen, int& hasDraw)
{
    flag_ = false;
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "Drawbmp");

    FILE *file = fdopen(fd, "r");
    if (file == NULL) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fdopen failed!");
        return;
    }
    
    if (fseek(file, foff, SEEK_SET) != 0) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fseek failed!");
        fclose(file);
        return;
    }
    
    if (flen <= 0) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "ResfdExecuteCB fseek failed!");
        fclose(file);
        return;
    }
    unsigned char *mediaData = new unsigned char[flen];
    if (mediaData == NULL) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "new buffer failed!");
        fclose(file);
        return;
    }
    size_t readCnt = fread(mediaData, sizeof(unsigned char), flen, file);
    if (readCnt > 0) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "readcnt: %{public}zu", readCnt);
    }

    int width = 0;
    int height = 0;
    unsigned char *pdata = mediaData + NUM_18;
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "width: %{public}d", *((uint32_t *)pdata));
    width = *((uint32_t *)pdata);
    pdata = mediaData + NUM_18 + NUM_4;
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "height: %{public}d", *((uint32_t *)pdata));
    height = *((uint32_t *)pdata);

    float vertices[] = {
        // positions          // colors           // texture coords
         1.0f,  1.0f, 0.0f,   1.0f, 0.0f, 0.0f,   2.0f, 2.0f, // top right
         1.0f,  -1.0f, 0.0f,   0.0f, 1.0f, 0.0f,   2.0f, -1.0f, // bottom right
         -1.0f,  -1.0f, 0.0f,   0.0f, 0.0f, 1.0f,   -1.0f, -1.0f, // bottom left
         -1.0f,  1.0f, 0.0f,   1.0f, 1.0f, 0.0f,   -1.0f, 2.0f  // top left
    };

    unsigned int indices[] = {
        0, 1, 3, // first triangle
        1, 2, 3  // second triangle
    };
    unsigned int VBO = 0;
    unsigned int VAO = 0;
    unsigned int EBO = 0;
    glGenVertexArrays(1, &VAO);
    glGenBuffers(1, &VBO);
    glGenBuffers(1, &EBO);

    glBindVertexArray(VAO);

    glBindBuffer(GL_ARRAY_BUFFER, VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(indices), indices, GL_STATIC_DRAW);

    // position attribute
    glVertexAttribPointer(0, NUM_3, GL_FLOAT, GL_FALSE, NUM_8 * sizeof(float), (void*)0);
    glEnableVertexAttribArray(0);
    // color attribute
    glVertexAttribPointer(1, NUM_3, GL_FLOAT, GL_FALSE, NUM_8 * sizeof(float), (void*)(NUM_3 * sizeof(float)));
    glEnableVertexAttribArray(1);
    // texture coord attribute
    glVertexAttribPointer(NUM_2, NUM_2, GL_FLOAT, GL_FALSE, NUM_8 * sizeof(float), (void*)(NUM_6 * sizeof(float)));
    glEnableVertexAttribArray(NUM_2);

    // load and create a texture
    // -------------------------
    unsigned int texture;
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);
    // all upcoming GL_TEXTURE_2D operations now have effect on this texture object
    // set the texture wrapping parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    // set texture wrapping to GL_CLAMP_TO_EDGE (default wrapping method)
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
    // set texture filtering parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    // load image, create texture and generate mipmaps
    
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, width, height, 0, GL_RGB, GL_UNSIGNED_BYTE, mediaData);
    glGenerateMipmap(GL_TEXTURE_2D);

    glClearColor(0.2f, 0.3f, 0.3f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    glBindTexture(GL_TEXTURE_2D, texture);

    glUseProgram(program_);

    glBindVertexArray(VAO);
    glDrawElements(GL_TRIANGLES, NUM_6, GL_UNSIGNED_INT, 0);

    eglSwapBuffers(eglDisplay_, eglSurface_);

    hasDraw = 1;
    flag_ = true;
}

void EGLCore::Draw(int& hasDraw)
{
    flag_ = false;
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "Draw");
    GLint position = PrepareDraw();
    if (position == POSITION_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Draw get position failed");
        return;
    }

    if (!ExecuteDrawBG(position, QL_BACKGROUND_COLOR,
        BACKGROUND_RECTANGLE_VERTICES, sizeof(BACKGROUND_RECTANGLE_VERTICES))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Draw execute draw background failed");
        return;
    }

    // Divided into five quadrilaterals and calculate one of the quadrilateral's Vertices
    GLfloat rotateX = 0;
    GLfloat rotateY = FIFTY_PERCENT * height_;
    GLfloat centerX = 0;
    // Convert DEG(54° & 18°) to RAD
    GLfloat centerY = -rotateY * (M_PI / NUM_180 * NUM_54) * (M_PI / NUM_180 * NUM_54);
    // Convert DEG(18°) to RAD
    GLfloat leftX = -rotateY * (M_PI / NUM_180 * NUM_18);
    GLfloat leftY = 0;
    // Convert DEG(18°) to RAD
    GLfloat rightX = rotateY * (M_PI / NUM_180 * NUM_18);
    GLfloat rightY = 0;

    const GLfloat shapeVertices[] = { centerX / width_, centerY / height_, leftX / width_, leftY / height_,
        rotateX / width_, rotateY / height_, rightX / width_, rightY / height_ };

    if (!ExecuteDrawStar(position, DRAW_COLOR, shapeVertices, sizeof(shapeVertices))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Draw execute draw shape failed");
        return;
    }

    if (!FinishDraw()) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Draw FinishDraw failed");
        return;
    }
    hasDraw = 1;

    flag_ = true;
}

void EGLCore::ChangeColor(int& hasChangeColor)
{
    if (!flag_) {
        return;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "EGLCore", "ChangeColor");
    GLint position = PrepareDraw();
    if (position == POSITION_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ChangeColor get position failed");
        return;
    }

    if (!ExecuteDrawBG(position, SLH_BACKGROUND_COLOR,
        BACKGROUND_RECTANGLE_VERTICES, sizeof(BACKGROUND_RECTANGLE_VERTICES))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ChangeColor execute draw background failed");
        return;
    }

    // Divided into five quadrilaterals and calculate one of the quadrilateral's Vertices
    GLfloat rotateX = 0;
    GLfloat rotateY = FIFTY_PERCENT * height_;
    GLfloat centerX = 0;
    // Convert DEG(54° & 18°) to RAD
    GLfloat centerY = -rotateY * (M_PI / NUM_180 * NUM_54) * (M_PI / NUM_180 * NUM_18);
    // Convert DEG(18°) to RAD
    GLfloat leftX = -rotateY * (M_PI / NUM_180 * NUM_18);
    GLfloat leftY = 0;
    // Convert DEG(18°) to RAD
    GLfloat rightX = rotateY * (M_PI / NUM_180 * NUM_18);
    GLfloat rightY = 0;

    const GLfloat shapeVertices[] = { centerX / width_, centerY / height_, leftX / width_, leftY / height_,
        rotateX / width_, rotateY / height_, rightX / width_, rightY / height_ };

    if (!ExecuteDrawNewStar(0, CHANGE_COLOR, shapeVertices, sizeof(shapeVertices))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Draw execute draw shape failed");
        return;
    }

    // Convert DEG(72°) to RAD
    GLfloat rad = M_PI / NUM_180 * NUM_72;
    // Rotate four times
    for (int i = 0; i < NUM_4; ++i) {
        Rotate2d(centerX, centerY, &rotateX, &rotateY, rad);
        Rotate2d(centerX, centerY, &leftX, &leftY, rad);
        Rotate2d(centerX, centerY, &rightX, &rightY, rad);
        const GLfloat shapeVertices[] = { centerX / width_, centerY / height_, leftX / width_, leftY / height_,
            rotateX / width_, rotateY / height_, rightX / width_, rightY / height_ };

        if (!ExecuteDrawNewStar(position, CHANGE_COLOR, shapeVertices, sizeof(shapeVertices))) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Draw execute draw shape failed");
            return;
        }
    }

    if (!FinishDraw()) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ChangeColor FinishDraw failed");
    }
    hasChangeColor = 1;
}

GLint EGLCore::PrepareDraw()
{
    if ((eglDisplay_ == nullptr) || (eglSurface_ == nullptr) || (eglContext_ == nullptr) ||
        (!eglMakeCurrent(eglDisplay_, eglSurface_, eglSurface_, eglContext_))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "PrepareDraw: param error");
        return POSITION_ERROR;
    }

    // The gl function has no return value.
    glViewport(DEFAULT_X_POSITION, DEFAULT_Y_POSITION, width_, height_);
    glClearColor(GL_RED_DEFAULT, GL_GREEN_DEFAULT, GL_BLUE_DEFAULT, GL_ALPHA_DEFAULT);
    glClear(GL_COLOR_BUFFER_BIT);
    glUseProgram(program_);

    return glGetAttribLocation(program_, POSITION_NAME);
}

bool EGLCore::ExecuteDrawBG(GLint position, const GLfloat* color, const GLfloat shapeVertices[], unsigned long vertSize)
{
    if ((position > 0) || (color == nullptr) || (vertSize / sizeof(shapeVertices[0])) != SHAPE_VERTICES_SIZE) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ExecuteDraw: param error");
        return false;
    }

    // The gl function has no return value.
    glVertexAttribPointer(position, POINTER_SIZE, GL_FLOAT, GL_FALSE, 0, shapeVertices);
    glEnableVertexAttribArray(position);
    glVertexAttrib4fv(1, color);
    glDrawArrays(GL_TRIANGLE_FAN, 0, TRIANGLE_FAN_SIZE);
    glDisableVertexAttribArray(position);

    return true;
}

bool EGLCore::ExecuteDrawStar(
    GLint position, const GLfloat* color, const GLfloat shapeVertices[], unsigned long vertSize)
{
    if ((position > 0) || (color == nullptr) || (vertSize / sizeof(shapeVertices[0])) != SHAPE_VERTICES_SIZE) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ExecuteDraw: param error");
        return false;
    }

    // The gl function has no return value.
    glVertexAttribPointer(position, POINTER_SIZE, GL_FLOAT, GL_FALSE, 0, shapeVertices);
    glVertexAttribPointer(1, POINTER_SIZE, GL_FLOAT, GL_FALSE, 0, color);
    glEnableVertexAttribArray(position);
    glEnableVertexAttribArray(1);
    glVertexAttrib4fv(1, color);
    glDrawArrays(GL_TRIANGLE_FAN, 0, TRIANGLE_FAN_SIZE);
    glDisableVertexAttribArray(position);
    glDisableVertexAttribArray(1);
    
    return true;
}

bool EGLCore::ExecuteDrawNewStar(
    GLint position, const GLfloat* color, const GLfloat shapeVertices[], unsigned long vertSize)
{
    if ((position > 0) || (color == nullptr) || (vertSize / sizeof(shapeVertices[0])) != SHAPE_VERTICES_SIZE) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "ExecuteDraw: param error");
        return false;
    }

    // The gl function has no return value.
    glVertexAttribPointer(position, POINTER_SIZE, GL_FLOAT, GL_FALSE, 0, shapeVertices);
    glEnableVertexAttribArray(position);
    glVertexAttrib4fv(1, color);
    glDrawArrays(GL_TRIANGLE_FAN, 0, TRIANGLE_FAN_SIZE);
    glDisableVertexAttribArray(position);

    return true;
}

void EGLCore::Rotate2d(GLfloat centerX, GLfloat centerY, GLfloat* rotateX, GLfloat* rotateY, GLfloat theta)
{
    GLfloat tempX = cos(theta) * (*rotateX - centerX) - sin(theta) * (*rotateY - centerY);
    GLfloat tempY = sin(theta) * (*rotateX - centerX) + cos(theta) * (*rotateY - centerY);
    *rotateX = tempX + centerX;
    *rotateY = tempY + centerY;
}

bool EGLCore::FinishDraw()
{
    // The gl function has no return value.
    glFlush();
    glFinish();
    return eglSwapBuffers(eglDisplay_, eglSurface_);
}

GLuint EGLCore::LoadShader(GLenum type, const char* shaderSrc)
{
    if ((type <= 0) || (shaderSrc == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "glCreateShader type or shaderSrc error");
        return PROGRAM_ERROR;
    }

    GLuint shader = glCreateShader(type);
    if (shader == 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "glCreateShader unable to load shader");
        return PROGRAM_ERROR;
    }

    // The gl function has no return value.
    glShaderSource(shader, 1, &shaderSrc, nullptr);
    glCompileShader(shader);

    GLint compiled;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (compiled != 0) {
        return shader;
    }

    GLint infoLen = 0;
    glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &infoLen);
    if (infoLen <= 1) {
        glDeleteShader(shader);
        return PROGRAM_ERROR;
    }

    char* infoLog = (char*)malloc(sizeof(char) * (infoLen + 1));
    if (infoLog != nullptr) {
        glGetShaderInfoLog(shader, infoLen, nullptr, infoLog);
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "glCompileShader error = %s", infoLog);
        free(infoLog);
        infoLog = nullptr;
    }
    glDeleteShader(shader);
    return PROGRAM_ERROR;
}

void EGLCore::checkCompileErrors(unsigned int shader, std::string type)
{
    int success;
    char infoLog[NUM_1024];
    if (type != "PROGRAM") {
        glGetShaderiv(shader, GL_COMPILE_STATUS, &success);
        if (!success) {
            glGetShaderInfoLog(shader, NUM_1024, NULL, infoLog);
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore",
                "ERROR::SHADER_COMPILATION_ERROR of type: %{public}s", type.c_str());
        }
    } else {
        glGetProgramiv(shader, GL_LINK_STATUS, &success);
        if (!success) {
            glGetProgramInfoLog(shader, NUM_1024, NULL, infoLog);
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore",
                "ERROR::PROGRAM_LINKING_ERROR of type: %{public}s", type.c_str());
        }
    }
}

GLuint EGLCore::TRCreateProgram(const char *vertexShader, const char *fragShader)
{
    if ((vertexShader == nullptr) || (fragShader == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore",
                     "createProgram: vertexShader or fragShader is null");
        return PROGRAM_ERROR;
    }

    unsigned int vertex = 0;
    unsigned int fragment = 0;
    // vertex shader
    vertex = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertex, 1, &vertexShader, NULL);
    glCompileShader(vertex);
    checkCompileErrors(vertex, "VERTEX");
    // fragment Shader
    fragment = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragment, 1, &fragShader, NULL);
    glCompileShader(fragment);
    checkCompileErrors(fragment, "FRAGMENT");

    GLuint program = glCreateProgram();
    if (program == PROGRAM_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram program error");
        glDeleteShader(vertex);
        glDeleteShader(fragment);
        return PROGRAM_ERROR;
    }

    // The gl function has no return value.
    glAttachShader(program, vertex);
    glAttachShader(program, fragment);
    glLinkProgram(program);
    checkCompileErrors(program, "PROGRAM");
    GLint linked;
    glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (linked != 0) {
        glDeleteShader(vertex);
        glDeleteShader(fragment);
        return program;
    }

    OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram linked error");
    GLint infoLen = 0;
    glGetProgramiv(program, GL_INFO_LOG_LENGTH, &infoLen);
    if (infoLen > 1) {
        char *infoLog = (char *)malloc(sizeof(char) * (infoLen + 1));
        glGetProgramInfoLog(program, infoLen, nullptr, infoLog);
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "glLinkProgram error = %{public}s", infoLog);
        free(infoLog);
        infoLog = nullptr;
    }
    glDeleteShader(vertex);
    glDeleteShader(fragment);
    glDeleteProgram(program);
    return PROGRAM_ERROR;
}

GLuint EGLCore::CreateProgram(const char* vertexShader, const char* fragShader)
{
    if ((vertexShader == nullptr) || (fragShader == nullptr)) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram: vertexShader or fragShader is null");
        return PROGRAM_ERROR;
    }

    GLuint vertex = LoadShader(GL_VERTEX_SHADER, vertexShader);
    if (vertex == PROGRAM_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram vertex error");
        return PROGRAM_ERROR;
    }

    GLuint fragment = LoadShader(GL_FRAGMENT_SHADER, fragShader);
    if (fragment == PROGRAM_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram fragment error");
        return PROGRAM_ERROR;
    }

    GLuint program = glCreateProgram();
    if (program == PROGRAM_ERROR) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram program error");
        glDeleteShader(vertex);
        glDeleteShader(fragment);
        return PROGRAM_ERROR;
    }

    // The gl function has no return value.
    glAttachShader(program, vertex);
    glAttachShader(program, fragment);
    glLinkProgram(program);

    GLint linked;
    glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (linked != 0) {
        glDeleteShader(vertex);
        glDeleteShader(fragment);
        return program;
    }

    OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "createProgram linked error");
    GLint infoLen = 0;
    glGetProgramiv(program, GL_INFO_LOG_LENGTH, &infoLen);
    if (infoLen > 1) {
        char* infoLog = (char*)malloc(sizeof(char) * (infoLen + 1));
        glGetProgramInfoLog(program, infoLen, nullptr, infoLog);
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "glLinkProgram error = %s", infoLog);
        free(infoLog);
        infoLog = nullptr;
    }
    glDeleteShader(vertex);
    glDeleteShader(fragment);
    glDeleteProgram(program);
    return PROGRAM_ERROR;
}

void EGLCore::UpdateSize(int width, int height)
{
    width_ = width;
    height_ = height;
    if (width_ > 0) {
        widthPercent_ = FIFTY_PERCENT * height_ / width_;
    }
}

void EGLCore::Release()
{
    if ((eglDisplay_ == nullptr) || (eglSurface_ == nullptr) || (!eglDestroySurface(eglDisplay_, eglSurface_))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Release eglDestroySurface failed");
    }

    if ((eglDisplay_ == nullptr) || (eglContext_ == nullptr) || (!eglDestroyContext(eglDisplay_, eglContext_))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Release eglDestroyContext failed");
    }

    if ((eglDisplay_ == nullptr) || (!eglTerminate(eglDisplay_))) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "EGLCore", "Release eglTerminate failed");
    }
}
} // namespace NativeXComponentSample
