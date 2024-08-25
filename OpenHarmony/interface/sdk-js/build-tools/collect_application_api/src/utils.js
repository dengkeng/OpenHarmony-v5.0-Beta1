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

const JSON5 = require('json5');
const path = require('path');
const fs = require('fs');

class Project {
  constructor(projectPath, nonProject) {
    this.projectPath = projectPath;
    this.nonProject = nonProject;
    this.logTag = 'Project';
  }

  getPath() {
    return this.projectPath;
  }

  getProfile() {
    if (!this.profile) {
      const buildProfilePath = path.resolve(this.projectPath, 'build-profile.json5');
      if (!fs.existsSync(buildProfilePath)) {
        Logger.error(this.logTag, 'build-profile.json5 can\'t be found, is it an openharmony project?');
        return this.profile;
      }
      const profileContent = fs.readFileSync(buildProfilePath, 'utf-8');
      try {
        this.profile = JSON5.parse(profileContent);
      } catch (ex) {
        Logger.error(this.logTag, `parse build-profile.json error: ${JSON.stringify(ex)}`);
      }
    }
    return this.profile;
  }

  getAppSdkVersion() {
    const profile = this.getProfile();

    if (!profile) {
      return undefined;
    }

    if (!profile.app) {
      return undefined;
    }

    if (profile.app.compileSdkVersion) {
      return profile.app.compileSdkVersion;
    }

    if (profile.app.products) {
      const compileSdkVersion = profile.app.products[0].compileSdkVersion;
      if (typeof compileSdkVersion === 'number') {
        return compileSdkVersion;
      }
      const version = compileSdkVersion.match(/\((.+)\)/g)[0].replace(/\(|\)/g, '');
      return version;
    }
    return undefined;
  }

  getAppSdkPath() {
    if (this.sdkPath) {
      return this.sdkPath;
    }
    const localPropertiesPath = path.resolve(this.projectPath, 'local.properties');
    if (!fs.existsSync(localPropertiesPath)) {
      Logger.error(this.logTag, 'unable to get the sdk path of the project, specify it using the --sdk or --sdkRoot');
      return this.sdkPath;
    }
    const properties = this.parseProperty(localPropertiesPath);
    this.sdkPath = properties.get('sdk.dir');
    return this.sdkPath;
  }

  parseProperty(propertyFilePath) {
    const properties = fs.readFileSync(propertyFilePath, 'utf-8');
    const lines = properties.split('\n');
    const propertyRegExp = new RegExp(/(.*)=(.*)/);
    const map = new Map();
    lines.forEach((line) => {
      if (line.startsWith('#')) {
        return;
      }
      const expArray = line.match(propertyRegExp);
      const MATCHED_RESULT_NUMBER = 3;
      const KEY_INDEX = 1;
      const VALUE_INDEX = 2;
      if (expArray && expArray.length === MATCHED_RESULT_NUMBER) {
        map.set(expArray[KEY_INDEX].trim(), expArray[VALUE_INDEX].trim());
      }
    });
    return map;
  }

  /**
   * 获取应用的源码列表
   *
   * @returns
   */
  getAppSources(isIncludeTest) {
    if (this.nonProject) {
      return this.getNonProjectAppSources();
    }
    const profile = this.getProfile();
    if (!profile || !profile.modules || profile.modules.length === 0) {
      return new Set();
    }
    const moduleSrcPaths = [];
    profile.modules.forEach((module) => {
      if (module.srcPath) {
        moduleSrcPaths.push(path.resolve(this.projectPath, module.srcPath));
      }
    });
    const appSources = [];
    moduleSrcPaths.forEach((moduleSrc) => {
      appSources.push(...this.getModuleSource(moduleSrc, isIncludeTest));
    });
    return new Set(appSources);
  }

  getNonProjectAppSources() {
    Logger.info(this.logTag, 'find source files in non-project');
    const appSources = [];
    this.listSourceFiles(this.projectPath, appSources);
    return new Set(appSources);
  }

  getModuleSource(modulePath, isIncludeTest) {
    const sourceSets = ['src/main/ets'];
    if (isIncludeTest) {
      sourceSets.push(...['src/ohosTest/ets']);
    }
    const sources = [];
    sourceSets.forEach((sourcePath) => {
      const srcPath = path.resolve(modulePath, sourcePath);
      this.listSourceFiles(srcPath, sources);
    });
    if (sources.length === 0) {
      Logger.info(this.logTag, `can't find source file in ${this.projectPath}`);
    }
    return sources;
  }

  listSourceFiles(srcPath, dest) {
    if (fs.existsSync(srcPath)) {
      Logger.info(this.logTag, `find source code in ${srcPath}`);
      FileSystem.listFiles(srcPath, (filePath) => {
        const fileName = path.basename(filePath);
        return fileName.endsWith('.ts') || fileName.endsWith('.ets');
      }, dest);
    }
  }
}

class Sdk {

  /**
   * 
   * @param {Project} project 应用工程对象
   * @param {string} sdkEtsPath 指向sdk中ets目录的路径
   * @param {string} sdkRoot sdk根目录
   */
  constructor(project, sdkEtsPath, sdkRoot) {
    this.project = project;
    this.sdkEtsPath = sdkEtsPath;
    this.sdkRoot = sdkRoot;
  }

  getPath() {
    if (this.sdkEtsPath) {
      return this.sdkEtsPath;
    }
    if (this.sdkApiRoot) {
      return this.sdkApiRoot;
    }
    const sdkVersion = this.project.getAppSdkVersion();
    const sdkDir = this.sdkRoot || this.project.getAppSdkPath();
    if (sdkVersion && sdkDir) {
      this.sdkApiRoot = path.resolve(sdkDir, `${sdkVersion}`, 'ets');
    }
    return this.sdkApiRoot;
  }

  /**
   * 获取SDK的d.ts文件列表
   *
   * @param {string} sdkRoot
   * @returns
   */
  getApiLibs() {
    if (this.apiLibs) {
      return this.apiLibs;
    }
    this.apiLibs = [];
    this.listDtsFiles('api', this.apiLibs);
    return this.apiLibs;
  }

  getComponentLibs() {
    if (this.componentLibs) {
      return this.componentLibs;
    }
    this.componentLibs = [];
    this.listDtsFiles('component', this.componentLibs);
    return this.componentLibs;
  }

  getESLibs(libPath) {
    if (!process.env.bundleMode) {
      return [];
    }
    Logger.info('Sdk', `find ES libs in ${libPath}`);
    if (this.esLibs) {
      return this.esLibs;
    }
    this.esLibs = [];
    FileSystem.listFiles(libPath, (filePath) => path.basename(filePath).endsWith('.d.ts'), this.esLibs);
    FileSystem.listFiles(libPath, (filePath) => path.basename(filePath).endsWith('.d.ets'), this.esLibs);
    return this.esLibs;
  }

  listDtsFiles(dir, dest) {
    const sdkRoot = this.getPath();
    if (!sdkRoot) {
      return;
    }
    const subDir = path.resolve(sdkRoot, dir);
    FileSystem.listFiles(subDir, (filePath) => path.basename(filePath).endsWith('.d.ts'), dest);
    FileSystem.listFiles(subDir, (filePath) => path.basename(filePath).endsWith('.d.ets'), dest);
  }
}

class FileSystem {
  static listFiles(dir, filter, dest) {
    const files = fs.readdirSync(dir);
    files.forEach((element) => {
      const filePath = path.join(dir, element);
      const status = fs.statSync(filePath);
      if (status.isDirectory()) {
        this.listFiles(filePath, filter, dest);
      } else if (filter(filePath)) {
        dest.push(this.convertToPosixPath(filePath));
      }
    });
  }

  static convertToPosixPath(filePath) {
    return filePath.split(path.sep).join(path.posix.sep);
  }

  static isInDirectory(parentDir, subPath) {
    const relative = path.relative(parentDir, subPath);
    return (relative === '' || !relative.startsWith('..')) && !path.isAbsolute(relative);
  }

  static listAllAppDirs(parentDir) {
    const dest = [];
    this.listDirectory(parentDir, dest, (filePath) => {
      const buildProfilePath = path.resolve(filePath, 'build-profile.json5');
      if (!fs.existsSync(buildProfilePath)) {
        return false;
      }
      const profileContent = fs.readFileSync(buildProfilePath, 'utf-8');
      const profile = JSON5.parse(profileContent);
      return profile.app && profile.modules;
    }, (filePath) => {
      return filePath;
    });
    return dest;
  }

  static listDirectory(dir, dest, filter, visitChildren) {
    const files = fs.readdirSync(dir);
    files.forEach((element) => {
      const filePath = path.join(dir, element);
      const status = fs.statSync(filePath);
      if (status.isDirectory()) {
        if (filter(filePath)) {
          dest.push(filePath);
        } else if (visitChildren(filePath)) {
          this.listDirectory(filePath, dest, filter, visitChildren);
        }
      }
    });
  }
}

class Logger {
  static INFO = 0;
  static WARN = 1;
  static ERROR = 2;
  static logs = '';
  static LEVEL_NAME = new Map([
    [this.INFO, 'I'],
    [this.WARN, 'W'],
    [this.ERROR, 'E']
  ]);

  static info(tag, message) {
    this.wrap(this.INFO, tag, message);
  }

  static warn(tag, message) {
    this.wrap(this.WARN, tag, message);
  }

  static error(tag, message) {
    this.wrap(this.ERROR, tag, message);
  }

  static wrap(level, tag, message) {
    const timeStamp = `${this.formatDate(Date.now(), 'Y-M-D H:m:s:x')}`;
    const logMessage = `${timeStamp} ${this.getLevelName(level)} [${tag}] ${message}`;
    console.log(logMessage);
  }

  static flush(output) {
    const logName = path.resolve(output, `${this.formatDate(Date.now(), 'Y-M-D-Hmsx')}.log`);
    fs.writeFileSync(logName, this.logs);
    this.info('Logger', `log is in ${logName}`);
  }

  static getLevelName(level) {
    if (this.LEVEL_NAME.has(level)) {
      return this.LEVEL_NAME.get(level);
    }
    return this.LEVEL_NAME.get(this.INFO);
  }

  static formatDate(time, format) {
    const date = new Date(time);
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hour = date.getHours();
    const min = date.getMinutes();
    const sec = date.getSeconds();
    const mis = date.getMilliseconds();
    let dateStr = format.replace('Y', `${year}`);
    dateStr = dateStr.replace('M', `${month}`);
    dateStr = dateStr.replace('D', `${day}`);
    dateStr = dateStr.replace('H', `${hour}`);
    dateStr = dateStr.replace('m', `${min}`);
    dateStr = dateStr.replace('s', `${sec}`);
    dateStr = dateStr.replace('x', `${mis}`);
    return dateStr;
  }
}

exports.Project = Project;
exports.Sdk = Sdk;
exports.FileSystem = FileSystem;
exports.Logger = Logger;