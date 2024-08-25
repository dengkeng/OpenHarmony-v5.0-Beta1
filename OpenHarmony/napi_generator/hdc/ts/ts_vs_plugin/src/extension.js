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
const re = require("./gen/tools/VsPluginRe");
const { VsPluginLog } = require("./gen/tools/VsPluginLog");
const { detectPlatform, readFile } = require('./gen/tools/VsPluginTool');
const path = require('path');
var exeFilePath = null;
var globalPanel = null;

var importToolChain = false;
var extensionIds = [];
var nextPluginId = null;
// this method is called when your extension is activated
// your extension is activated the very first time the command is executed

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "ts-gen" is now active!');
	let disposable = register(context, 'generate_ts');
	let disposableMenu = register(context, 'generate_ts_menu');
	context.subscriptions.push(disposable);
	context.subscriptions.push(disposableMenu);
	
	var platform = detectPlatform();
	if (platform == 'win') {
		exeFilePath = __dirname + "/napi_generator-win.exe";
	} else if (platform == 'mac') {
		exeFilePath = __dirname + "/napi_generator-macos";
	} else if (platform == 'Linux') {
		exeFilePath = __dirname + "/napi_generator-linux";
	}
}

function executorH2Ts(name, genDir) {
	var command = exeFilePath + " -f " + name + " -o " + genDir + " -t true";
	var exec = require('child_process').exec;
	exec(command, function (error, stdout, stderr) {
		VsPluginLog.logInfo('VsPlugin: stdout =' + stdout + ", stderr =" + stderr);
		if (error || stdout.indexOf("success") < 0) {
			vscode.window.showErrorMessage("genError:" + (error != null ? error : "") + stdout);
			return VsPluginLog.logError("VsPlugin:" + error + stdout);
		}
		vscode.window.showInformationMessage("Generated successfully");
	});
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
			'Generate Ts Frame', // Title of the panel displayed to the user
			vscode.ViewColumn.Two, // Display the WebView panel in the form of new columns in the editor
			{
				enableScripts: true, // Enable or disable JS, default is Enable
				retainContextWhenHidden: true, // Keep the WebView state when it is hidden to avoid being reset
			}
		);
		if (typeof(boolValue) == 'boolean' && Array.isArray(items)) {
			if (boolValue == true) {
				//遍历数组item,查看当前插件id是数组的第几个元素，并拿出下一个元素，并判断当前id是否是最后一个元素并做相应处理
				let myExtensionId = 'kaihong.ts-gen';
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
			if (msg == "cancel") {
				globalPanel.dispose();
			} 
			else if(msg == "h2ts") {
				checkReceiveMsg(message);
			}else {
				selectPath(globalPanel, message);
			}
		}, undefined, context.subscriptions);
    // 路径有效性判断
    if (uri.fsPath !== undefined) {
      let fn = re.getFileInPath(uri.fsPath);
      let tt = re.match("([a-zA-Z_0-9]+.h)", fn);
      var result = {
        msg: "selectHFilePath",
        path: tt ? uri.fsPath : ""
      }
      globalPanel.webview.postMessage(result);
    }
	});
	return disposable;
}

function checkReceiveMsg(message) {
	let name = message.fileNames;
	let genDir = message.genDir;
	let buttonName = message.buttonName;
	name = re.replaceAll(name, " ", "");
	if ("" == name) {
		vscode.window.showErrorMessage("Please enter the path!");
		return;
	}
	if (exeFileExit()) {
		executorH2Ts(name, genDir);
		if (buttonName == 'Next') {
			startNextPlugin();
		}
	} else {
		vscode.window.showInformationMessage("Copy executable program to " + __dirname);
	}
}

/**
* 获取插件执行命令
*/
function nextPluginExeCommand(nextPluginId) {
    if (nextPluginId == "kaihong.ApiScan") {
		return 'api_scan';
	} else if (nextPluginId == "kaihong.gn-gen") {
		return 'generate_gn';
	} else if (nextPluginId == "kaihong.service-gen") {
		return 'generate_service';
	} else if (nextPluginId == "kaihong.ts-gen") {
		return 'generate_ts';
	} else if (nextPluginId == "kaihong.napi-gen") {
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
* 选择本地目录/文件夹
*/
 function selectPath(panel, message) {
	let mode = 1;
	if (message.mode != undefined) {
		mode = message.mode;
	}
	const options = {
		canSelectMany: mode == 0 ? true : false,//是否可以选择多个
		openLabel: mode == 0 ? '选择文件' : '选择文件夹',//打开选择的右下角按钮label
		canSelectFiles: mode == 0 ? true : false,//是否选择文件
		canSelectFolders: mode == 0 ? false : true,//是否选择文件夹
		defaultUri:vscode.Uri.file(''),//默认打开本地路径
		filters: mode == 1 ? {} : { // 文件过滤选项，在文件夹选择模式下不可设置此配置，否则ubuntu系统下无法选择文件夹
			'Text files': ['h']
		} 
	};
   
	return vscode.window.showOpenDialog(options).then(fileUri => {
	   if (fileUri && fileUri[0]) {
		   console.log('Selected file: ' + fileUri[0].fsPath);
		   let filePath = "";
		   for (let index = 0; index < fileUri.length; index++) {
				filePath += fileUri[index].fsPath.concat(",");
		   }
		   var result = {
				msg: message.msg,
				path: filePath.length > 0 ? filePath.substring(0, filePath.length - 1) : filePath
				}
		   panel.webview.postMessage(result);
		   return fileUri[0].fsPath
	   }
   });
}

// this method is called when your extension is deactivated
function deactivate() { }

function getWebviewContent(context, importToolChain) {
	let data = readFile(__dirname + '/vs_plugin_view.html');
	data = getWebViewContent(context, '/vs_plugin_view.html');
	let content = data.toString();
	if (importToolChain) {
		content = content.replace('Ok', 'Next');
	}
	return content;
}

function getWebViewContent(context, templatePath) {
    const resourcePath = path.join(context.extensionPath, templatePath);
    const dirPath = path.dirname(resourcePath);
    let html = fs.readFileSync(resourcePath, 'utf-8');
    html = html.replace(/(<link.+?href="|<script.+?src="|<iframe.+?src="|<img.+?src=")(.+?)"/g, (m, $1, $2) => {
        if ($2.indexOf("https://") < 0) {
            return $1 + globalPanel.webview.asWebviewUri(vscode.Uri.file(path.resolve(dirPath, $2))) + '"';
        } else {
            return $1 + $2+'"';
        }
    });
    return html;
}

module.exports = {
	activate,
	deactivate
}