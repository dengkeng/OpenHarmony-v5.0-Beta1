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

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require('vscode');
const fs = require('fs');
const re = require('./gen/tools/VsPluginRe');
const { VsPluginLog } = require('./gen/tools/VsPluginLog');
const { detectPlatform, readFile } = require('./gen/tools/VsPluginTool');
const path = require('path');
const INVALID_INDEX = -1;
const SELECT_H_FILE = 2; // 选择.h文件
var exeFilePath = null;
var globalPanel = null;
var showInfoPanel = null;
var importToolChain = false;
var extensionIds = [];
var nextPluginId = null;
let configList = new Array();
let generateDir = '';
let cfgPath = '';

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  // Use the console to output diagnostic information (console.log) and errors (console.error)
  // This line of code will only be executed once when your extension is activated
  console.log('Congratulations, your extension "napi-gen" is now active!');
  let disposable = register(context, 'generate_napi');
  let disposableMenu = register(context, 'generate_napi_menu');
  context.subscriptions.push(disposable);
  context.subscriptions.push(disposableMenu);
  var platform = detectPlatform();
  if (platform == 'win') {
    exeFilePath = __dirname + '/napi_generator-win.exe';
  } else if (platform == 'mac') {
    exeFilePath = __dirname + '/napi_generator-macos';
  } else if (platform == 'Linux') {
    exeFilePath = __dirname + '/napi_generator-linux';
  }
}

function executor(name, genDir, mode, numberType, importIsCheck) {
  var exec = require('child_process').exec;
  exec(genCommand(name, genDir, mode, numberType, importIsCheck), function (error, stdout, stderr) {
    VsPluginLog.logInfo('VsPlugin: stdout =' + stdout + ', stderr =' + stderr);
    if (error || stdout.indexOf('success') < 0) {
      vscode.window.showErrorMessage('genError:' + (error != null ? error : '') + stdout);
      return VsPluginLog.logError('VsPlugin:' + error + stdout);
    }
    vscode.window.showInformationMessage('Generated successfully');
  });
}

function genCommand(name, genDir, mode, numberType, importIsCheck) {
  var genFileMode = mode == 0 ? ' -f ' : ' -d ';

  let genServiceCode = '';
  console.log('cfgPath: ' + cfgPath);
  // -s  判断是否存在文件 ，存在则加-s参数
  if (fs.existsSync(cfgPath)) {
    genServiceCode = ' -s ' + cfgPath;
    console.log('genServiceCode: ' + genServiceCode);
  }

  if (genDir === '') {
    return exeFilePath + genFileMode + name + genServiceCode;
  }
  return exeFilePath + genFileMode + name + ' -o ' + genDir + ' -n ' + numberType + ' -i ' + importIsCheck + genServiceCode;
}

function exeFileExit() {
  if (fs.existsSync(exeFilePath)) {
    return true;
  }
  return false;
}

function register(context, command) {
	let disposable = vscode.commands.registerCommand(command, function (uri, boolValue, items) {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		globalPanel = vscode.window.createWebviewPanel(
			'generate', // Identifies the type of WebView
			'Generate Napi Frame', // Title of the panel displayed to the user
			vscode.ViewColumn.Two, // Display the WebView panel in the form of new columns in the editor
			{
				enableScripts: true, // Enable or disable JS, default is Enable
				retainContextWhenHidden: true, // Keep the WebView state when it is hidden to avoid being reset
			}
		);

		if (typeof(boolValue) == 'boolean' && Array.isArray(items)) {
			if (boolValue == true) {
				//遍历数组item,查看当前插件id是数组的第几个元素，并拿出下一个元素，并判断当前id是否是最后一个元素并做相应处理
				let myExtensionId = 'kaihong.napi-gen';
				for (let i = 0; i < items.length; i++) {
					if (myExtensionId == items[i] && (i == items.length - 1)) {
						importToolChain = false;
					} else if (myExtensionId == items[i] && (i != items.length - 1)) {
						importToolChain = boolValue;
						nextPluginId = items[i + 1];
					}
					extensionIds.push(items[i]);
				}
			}
		}
		globalPanel.webview.html = getWebviewContent(context, importToolChain);
		let msg;
		globalPanel.webview.onDidReceiveMessage(message => {
      msg = message.msg;
      if (msg == 'cancel') {
        globalPanel.dispose();
      } else if (msg == 'param') {
        if (configList.length !== 0) {
          writeCfgJson();  // 写cfg.json文件
        }
        checkReceiveMsg(message);
      } else if (msg === 'config') {
        // 若选择文件夹或者选择了多个文件则不能配置业务代码
        if (message.mode !== 0 || message.interFile.indexOf(',') > 0) {
          vscode.window.showInformationMessage('选择文件夹或者多个文件时不能配置业务代码,请选择单个文件');
          console.error('选择文件夹或者多个文件时不能配置业务代码,请选择单个文件');
        } else if (trimAll(message.genDir).length <= 0) {
          vscode.window.showInformationMessage('请输入生成框架路径!');
          console.error('请输入生成框架路径!');
        } else {
          configServiceCode(message, context);
        }
      } else {
        selectPath(globalPanel, message);
      }
    }, undefined, context.subscriptions);
    // 路径有效性判断
    if (uri.fsPath !== undefined) {
      let fn = re.getFileInPath(uri.fsPath);
      let tt = re.match("((@ohos\.)*[a-zA-Z_0-9]+.d.ts)", fn);
      var result = {
        msg: "selectInterPath",
        path: tt ? uri.fsPath : ""
      }
      globalPanel.webview.postMessage(result);
    }
  });
  return disposable;
}

// 去除字符串空格
function trimAll(str) {
  return str.split(/[\t\r\f\n\s]*/g).join('');
}

function configServiceCode(message, context) {
  generateDir = message.genDir;
  // 创建新的面板显示config信息
  showInfoPanel = vscode.window.createWebviewPanel(
    'configWebview',
    'Config',
    vscode.ViewColumn.Two,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
    }
  );
  // 加载信息显示页面
  showInfoPanel.webview.html = getCommonWebViewContent(context, '/vs_showInfo_view.html');
  // 处理来自showInfo页面的信息
  showInfoPanel.webview.onDidReceiveMessage((showInfoMessage) => {
    handleConfigMsg(showInfoMessage, context);
  }, undefined, context.subscriptions);
}

function handleConfigMsg(showInfoMessage, context) {
  if (showInfoMessage.msg === 'configInfo') {
    if ((showInfoMessage.index !== INVALID_INDEX && showInfoMessage.type === 'update') || showInfoMessage.type === 'add') {
      // 配置界面
      showInfoPanel.webview.html = getCommonWebViewContent(context, '/vs_config_view.html');
      showInfoPanel.webview.postMessage({
        msg: 'updateData',
        type: showInfoMessage.type,
        index: showInfoMessage.index,
        updateInfo: showInfoMessage.updateInfo,
        genPath: generateDir,
      });
    } else {
      console.error('please choose one item to update!');
    }
  } else if (showInfoMessage.msg === 'saveData') {
    // 判断数据有效性
    if (validate(showInfoMessage.cfgInfo)) {
      // 处理来自 vs_config_view.html 的数据保存操作
      saveData(showInfoMessage.cfgInfo, showInfoMessage.type, showInfoMessage.index);
      // 返回 vs_showInfo_view.html 作为弹出窗口
      showInfoPanel.webview.html = getCommonWebViewContent(context, '/vs_showInfo_view.html');
      showInfoPanel.webview.postMessage({
        msg: 'initShowInfo',
        configList: getArrayListData(),
      });
    } else {
      vscode.window.showInformationMessage('配置的信息不能为空!');
      console.error('配置的信息不能为空!');
    }
  } else if (showInfoMessage.msg === 'deleteData') {
    deleteData(showInfoMessage.index);
    showInfoPanel.webview.html = getCommonWebViewContent(context, '/vs_showInfo_view.html');
    showInfoPanel.webview.postMessage({
      msg: 'deleteData',
      configList: getArrayListData(),
    });
  } else if (showInfoMessage.msg === 'cancelShowInfo') {
    showInfoPanel.dispose();
  } else if (showInfoMessage.msg === 'selectIncludeName' || showInfoMessage.msg === 'selectCppName') {
    selectConfigPath(showInfoPanel, showInfoMessage, generateDir);
  } else {
    console.log('showInfoMessage.msg = ' + showInfoMessage.msg);
  }
}

// 数据是否为空
function validate(data) {
  let includeName = data.includeName;
  let cppName = data.cppName;
  let interfaceName = data.interfaceName;
  let serviceCode = data.serviceCode;
  if (!isEmptyStr(includeName) && !isEmptyStr(cppName) && !isEmptyStr(interfaceName) && !isEmptyStr(serviceCode)) {
    return true;
  } else {
    return false;
  }
}

function isEmptyStr(str) {
  if (str.length !== 0) {
    return false;
  } else {
    return true;
  }
}

function checkReceiveMsg(message) {
  let mode = message.mode;
  let name = message.fileNames;
  let genDir = message.genDir;
  let numberType = message.numberType;
  let importIsCheck = message.importIsCheck;
  let buttonName = message.buttonName;
  checkMode(name, genDir, mode, numberType, importIsCheck);
  if (buttonName == 'Next') {
    startNextPlugin();
  }
}

/**
 * 将configList写入cfg.json文件
 */
function writeCfgJson() {
  let platform = detectPlatform();
  let json = JSON.stringify(configList);
  // 处理不同平台配置业务代码时换行符问题
  if (platform === 'win') {
    console.log('windows');
    json = json.replace(/\\\\r\\\\n/g, '\\n');
    json = json.replace(/\\\\n/g, '\\n');
  } else if (platform === 'Linux') {
    json = json.replace(/\\\\n/g, '\\n');
  } else if (platform === 'mac') {
    json = json.replace(/\\\\r/g, '\\r');
  }

  // 将JSON字符串写入文件
  if (generateDir !== '') {
    cfgPath = generateDir + '/cfg.json';
    try {
      // file written successfully
      fs.writeFileSync(cfgPath, json.toString());
    } catch (err) {
      console.error(err);
    }
  }
}

/**
 * 获取configList
 */
function getArrayListData() {
  return configList;
}

/**
 * 增加或者修改一项数据
 */
function saveData(cfgInfo, type, index) {
  if (type === 'add') {
    configList.push(cfgInfo);
  } else if (type === 'update') {
    configList[index] = cfgInfo;
  } else {
    console.error('type error, type is ' + type);
  }
}

/**
 * 删除一项数据
 */
function deleteData(index) {
  if (index !== -1) {
    configList.splice(index, 1);
  } else {
    console.error('please choose one item to delete!');
  }
}

/**
 * 获取插件执行命令
 */
function nextPluginExeCommand(nextPluginId) {
  if (nextPluginId == 'kaihong.ApiScan') {
    return 'api_scan';
  } else if (nextPluginId == 'kaihong.gn-gen') {
    return 'generate_gn';
  } else if (nextPluginId == 'kaihong.service-gen') {
    return 'generate_service';
  } else if (nextPluginId == 'kaihong.ts-gen') {
    return 'generate_ts';
  } else if (nextPluginId == 'kaihong.napi-gen') {
    return 'generate_napi';
  } else {
    return null;
  }
}

/**
 * 执行完毕后开启工具链中下一个插件
 */
function startNextPlugin() {
  const extension = vscode.extensions.getExtension(nextPluginId);
  if (extension) {
    let startNextPlugin = nextPluginExeCommand(nextPluginId);
    try {
      vscode.commands.executeCommand(startNextPlugin, '', importToolChain, extensionIds);
    } catch (error) {
      console.error(error);
    }
  }
}

/**
 * 选择本地 .h/.cpp 文件
 */
function selectConfigPath(panel, message, generateDir) {
  let mode = SELECT_H_FILE; // 选择.h文件
  if (message.mode !== undefined || message.mode !== null) {
    mode = message.mode;
  }
  const options = {
    canSelectMany: false, //是否可以选择多个
    openLabel: '选择文件', //打开选择的右下角按钮label
    canSelectFiles: true, //是否选择文件
    canSelectFolders: false, //是否选择文件夹
    defaultUri: vscode.Uri.file(''), //默认打开本地路径
    // 文件过滤选项，在文件夹选择模式下不可设置此配置，否则ubuntu系统下无法选择文件夹
    filters: mode === SELECT_H_FILE? { 'Text files': ['h', 'hpp', 'hxx'] }: { 'Text files': ['cpp', 'cc', 'C', 'cxx', 'c++'] },
  };

	return vscode.window.showOpenDialog(options).then(fileUri => {
    if (fileUri && fileUri[0]) {
      console.log('Selected file: ' + fileUri[0].fsPath);
      let fileObsPath = fileUri[0].fsPath;
      // 获取相对路径  相对于生成框架路径
      let filePath = path.relative(generateDir, fileObsPath);
      console.log('relative filePath: ' + filePath);
      var result = {
        msg: message.msg,
        path: filePath,
      };
      panel.webview.postMessage(result);
      return fileUri[0].fsPath;
    }
  });
}

/**
 * 选择本地目录/文件夹
 */
function selectPath(panel, message) {
  let mode = 1;
  if (message.mode != undefined) {
    mode = message.mode;
  }
  const options = {
    canSelectMany: mode == 0 ? true : false, //是否可以选择多个
    openLabel: mode == 0 ? '选择文件' : '选择文件夹', //打开选择的右下角按钮label
    canSelectFiles: mode == 0 ? true : false, //是否选择文件
    canSelectFolders: mode == 0 ? false : true, //是否选择文件夹
    defaultUri: vscode.Uri.file(''), //默认打开本地路径
    // 文件过滤选项，在文件夹选择模式下不可设置此配置，否则ubuntu系统下无法选择文件夹
    filters: mode == 1 ? {} : { 'Text files': ['d.ts'] },
  };

  return vscode.window.showOpenDialog(options).then((fileUri) => {
    if (fileUri && fileUri[0]) {
      console.log('Selected file: ' + fileUri[0].fsPath);
      let filePath = '';
      for (let index = 0; index < fileUri.length; index++) {
        filePath += fileUri[index].fsPath.concat(',');
      }
      var result = {
        msg: message.msg,
        path: filePath.length > 0? filePath.substring(0, filePath.length - 1): filePath,
      };
      panel.webview.postMessage(result);
      return fileUri[0].fsPath;
    }
  });
}

function checkMode(name, genDir, mode, numberType, importIsCheck) {
  name = re.replaceAll(name, ' ', '');
  if ('' == name) {
    vscode.window.showErrorMessage('Please enter the path!');
    return;
  }
  if (mode == 0) {
    if (name.indexOf('.') < 0) {
      vscode.window.showErrorMessage('Please enter the correct file path!');
      return;
    }
  } else {
    if (name.indexOf('.') > 0 || !fs.lstatSync(name).isDirectory()) {
      vscode.window.showErrorMessage('Please enter the correct folder folder!');
      return;
    }
  }

  if (exeFileExit()) {
    executor(name, genDir, mode, numberType, importIsCheck);
  } else {
    vscode.window.showInformationMessage('Copy executable program to ' + __dirname);
  }
}

// 获得配置页面和显示页面
function getCommonWebViewContent(context, html) {
  let data = getWebViewContent(context, html, showInfoPanel);
  let content = data.toString();
  return content;
}

// this method is called when your extension is deactivated
function deactivate() {}

function getWebviewContent(context, importToolChain) {
  let data = readFile(__dirname + '/vs_plugin_view.html');
  data = getWebViewContent(context, '/vs_plugin_view.html', globalPanel);
  let content = data.toString();
  if (importToolChain) {
    content = content.replace('Ok', 'Next');
  }
  return content;
}

function getWebViewContent(context, templatePath, panel) {
  const resourcePath = path.join(context.extensionPath, templatePath);
  const dirPath = path.dirname(resourcePath);
  let html = fs.readFileSync(resourcePath, 'utf-8');
  html = html.replace(/(<link.+?href="|<script.+?src="|<iframe.+?src="|<img.+?src=")(.+?)"/g, (m, $1, $2) => {
      if ($2.indexOf('https://') < 0) {
        return ($1 + panel.webview.asWebviewUri(vscode.Uri.file(path.resolve(dirPath, $2))) + '"');
      } else {
        return $1 + $2 + '"';
      }
    });
  return html;
}

module.exports = {
  activate,
  deactivate,
};
