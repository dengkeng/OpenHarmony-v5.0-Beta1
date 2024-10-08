#  AVRecorder Demo

###  Introduction

In this sample, you can use AVRecorder interfaces to record audio or video.

### Required Permissions

ohos.permission.MICROPHONE, which request the permission of microphone.

ohos.permission.CAMERA, which request the permission of camera.

ohos.permission.WRITE_MEDIA, which allows an app to write media files to the user's external storage.

### Usage

1. On the home page, you can either choose **Video Recording** or **Audio Recording** button according to your purpose.
2. Click the **Video Recording** button to switch to the video recording page. First, you can click the setting button to choose recording configurations. You can click the button on the top-right to check your configurations. You can click the start, pause, resume, stop button to control the recording process.
3. Click the **Audio Recording** button to switch to the audio recording page. You can click the start, pause, resume, stop button to control the recording process.
4. The files you have recorded can be found in Photos.

### Constraints

1. This sample can only be run on standard-system devices that use phone development board.
2. This sample is based on the stage model, which is supported from API version 9. You should manully fetch Full SDK from gitee and replace them in DevEco Studio.
3. DevEco Studio 3.1 (Build Version:3.1.0.200, built on Feburary 16, 2023) must be used.
3. Camera apis can only be used by system app. In order to run this sample,  you should generate signature manually with hap-sign-tool.

