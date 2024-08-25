/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

const { Project, Sdk, FileSystem, Logger } = require('./utils');
const { ApiWriter, ApiExcelWriter } = require('./api_writer');
const { SystemApiRecognizer } = require('./api_recognizer');
const { ReporterFormat } = require('./configs');
const ts = require('typescript');
const fs = require('fs');
const path = require('path');

class ProgramFactory {
  setLibPath(libPath) {
    this.libPath = libPath;
  }

  getETSOptions(componentLibs) {
    const tsconfig = require('../tsconfig.json');
    const etsConfig = tsconfig.compilerOptions.ets;
    etsConfig.libs = [...componentLibs];
    return etsConfig;
  }

  createProgram(rootNames, apiLibs, componentLibs, esLibs) {
    const compilerOption = {
      target: ts.ScriptTarget.ES2017,
      ets: this.getETSOptions([]),
      allowJs: false,
      lib: [...apiLibs, ...componentLibs, ...esLibs],
      module: ts.ModuleKind.CommonJS,
    };
    this.compilerHost = this.createCompilerHost({
      resolveModuleName: (moduleName) => {
        return this.resolveModuleName(moduleName, apiLibs);
      },
    }, compilerOption);

    if (this.libPath && fs.existsSync(this.libPath)) {
      Logger.info('ProgramFactory', `set default lib location: ${this.libPath}`);
      this.compilerHost.getDefaultLibLocation = () => {
        return this.libPath;
      };
    }
    return ts.createProgram({
      rootNames: [...rootNames],
      options: compilerOption,
      host: this.compilerHost,
    });
  }

  resolveModuleName(moduleName, libs) {
    if (moduleName.startsWith('@')) {
      const moduleFileName = `${moduleName}.d.ts`;
      const etsModuleFileName = `${moduleName}.d.ets`;
      for (const lib of libs) {
        if (lib.endsWith(moduleFileName) || lib.endsWith(etsModuleFileName)) {
          return lib;
        }
      }
    }
    return undefined;
  }

  createCompilerHost(moduleResolver, compilerOption) {
    const compilerHost = ts.createCompilerHost(compilerOption);
    compilerHost.resolveModuleNames = this.getResolveModuleNames(moduleResolver);
    return compilerHost;
  }

  getResolveModuleNames(moduleResolver) {
    return (moduleNames, containingFile, reusedNames, redirectedReference, options) => {
      const resolvedModules = [];
      for (const moduleName of moduleNames) {
        const moduleLookupLocaton = ts.resolveModuleName(moduleName, containingFile, options,
          this.moduleLookupResolutionHost());
        if (moduleLookupLocaton.resolvedModule) {
          resolvedModules.push(moduleLookupLocaton.resolvedModule);
        } else {
          const modulePath = moduleResolver.resolveModuleName(moduleName);
          const resolved = modulePath && ts.sys.fileExists(modulePath) ?
            { resolvedFileName: modulePath } :
            undefined;
          resolvedModules.push(resolved);
        }
      }
      return resolvedModules;
    };
  }

  moduleLookupResolutionHost() {
    return {
      fileExists: (fileName) => {
        return fileName && ts.sys.fileExists(fileName);
      },
      readFile: (fileName) => {
        ts.sys.readFile(fileName);
      },
    };
  }
}

class ApiCollector {
  constructor(argv) {
    const appProject = argv.app ? argv.app : (argv.dir ? argv.dir : undefined);
    if (!appProject) {
      throw 'app not found';
    }
    this.project = new Project(appProject, argv.dir !== undefined);
    this.sdk = new Sdk(this.project, argv.sdk, argv.sdkRoot);
    this.formatFlag = ReporterFormat.getFlag(argv.format);
    this.outputPath = !argv.output ? appProject : argv.output;
    this.logTag = 'ApiCollector';
    this.debugFlag = argv.debug;
    this.noRepeat = argv.noRepeat ? true : false;
  }

  setLibPath(libPath) {
    this.libPath = libPath;
    if (libPath && !fs.existsSync(this.libPath)) {
      Logger.warn(this.logTag, `${libPath} is not exist`);
    } else {
      Logger.info(this.logTag, `set lib path ${libPath}`);
    }
    return this;
  }

  setIncludeTest(isIncludeTest) {
    this.isIncludeTest = isIncludeTest;
    return this;
  }

  async start() {
    const sdkPath = this.sdk.getPath();
    if (!sdkPath || !fs.existsSync(sdkPath)) {
      return;
    }
    const handleFilePath = path.join(sdkPath, '/api/@internal/full/global.d.ts');
    const originalContent = fs.readFileSync(handleFilePath, 'utf-8');
    let newContent = originalContent.replace(/\import|export/g, '');
    fs.writeFileSync(handleFilePath, newContent);
    Logger.info(this.logTag, `scan app ${this.project.getPath()}`);
    Logger.info(this.logTag, `sdk is in ${sdkPath}`);
    const apiLibs = this.sdk.getApiLibs();
    const componentLibs = this.sdk.getComponentLibs();
    const eslibs = this.sdk.getESLibs(this.libPath);
    const appSourceSet = this.project.getAppSources(this.isIncludeTest);
    const programFactory = new ProgramFactory();
    programFactory.setLibPath(this.libPath);
    let program = programFactory.createProgram(appSourceSet, apiLibs, componentLibs, eslibs);

    if (this.debugFlag) {
      program.getSourceFiles().forEach((sf) => {
        Logger.info('ApiCollector', sf.fileName);
      });
    }

    let systemApiRecognizer = new SystemApiRecognizer(sdkPath);
    systemApiRecognizer.setTypeChecker(program.getTypeChecker());
    Logger.info(this.logTag, `start scanning ${this.project.getPath()}`);
    appSourceSet.forEach((appCodeFilePath) => {
      const canonicalFileName = programFactory.compilerHost.getCanonicalFileName(appCodeFilePath);
      const sourceFile = program.getSourceFileByPath(canonicalFileName);
      if (sourceFile) {
        if (this.debugFlag) {
          Logger.info(this.logTag, `scan ${sourceFile.fileName}`);
        }
        systemApiRecognizer.visitNode(sourceFile, sourceFile.fileName);
      } else {
        Logger.warn(this.logTag, `no sourceFile ${appCodeFilePath}`);
      }
    });
    Logger.info(this.logTag, `end scan ${this.project.getPath()}`);
    const apiWriter = this.getApiWriter();
    apiWriter.add(systemApiRecognizer.getApiInformations());
    // avoid oom
    systemApiRecognizer = undefined;
    program = undefined;
    await apiWriter.flush();
    fs.writeFileSync(handleFilePath, originalContent);
  }

  getApiWriter() {
    if (!this.apiWriter) {
      this.apiWriter = new ApiWriter(this.outputPath, this.formatFlag, this.noRepeat);
    }
    return this.apiWriter;
  }

  setApiWriter(apiWriter) {
    this.apiWriter = apiWriter;
  }
}

class MultiProjectApiCollector {
  constructor(argv) {
    this.argv = argv;
  }

  setLibPath(libPath) {
    this.libPath = libPath;
    if (libPath && !fs.existsSync(this.libPath)) {
      Logger.warn(this.logTag, `${libPath} is not exist`);
    } else {
      Logger.info(this.logTag, `set lib path ${libPath}`);
    }
    return this;
  }

  setIncludeTest(isIncludeTest) {
    this.isIncludeTest = isIncludeTest;
    return this;
  }

  async start() {
    const allApps = FileSystem.listAllAppDirs(this.argv.appDir);
    if (allApps.length === 0) {
      Logger.info('MultiProjectApiCollector', `project not found in ${this.argv.appDir}`);
      return;
    }
    const output = !this.argv.output ? this.argv.appDir : this.argv.output;
    const apiExcelWriter = new ApiExcelWriter(output);
    apiExcelWriter.close();
    allApps.forEach((app) => {
      if (app) {
        this.argv.app = app;
        const apiCollector = new ApiCollector(this.argv);
        apiCollector.setApiWriter(apiExcelWriter);
        apiCollector.setLibPath(this.libPath).setIncludeTest(this.isIncludeTest).start();
      }
    });
    apiExcelWriter.open();
    await apiExcelWriter.flush();
  }
}

exports.ApiCollector = ApiCollector;
exports.MultiProjectApiCollector = MultiProjectApiCollector;