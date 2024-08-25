/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import FileModel from '../../Model/FileModel';
import { Log, MediaSize } from '@ohos/common';
import { Constants, PageDirection, ColorCode } from '@ohos/common';
import { GlobalThisHelper, GlobalThisStorageKey } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import image from '@ohos.multimedia.image';
import { BusinessError } from '@ohos.base';

const canvasScale = 2
const to300DPI = 300/72
const TAG = 'PreviewComponent'

@Component
export struct PreviewComponent {

  @Consume('ImageCount') imageCount: number
  @Consume('CurrentIndex') currentIndex: number
  @Consume('IsGlobalDisable') isGlobalDisable: boolean
  @Consume('PreviewCompHeight')@Watch('onHeightLoad') previewCompHeight: number//预览区组件高度

  @Consume('IsBorderless')isBorderless: boolean
  @Consume('PrintRange')@Watch('onPrintRangeChange')  printRange: Array<number>
  @Link @Watch('onPageDirectionChange') pageDirection:number
  @Link @Watch('onMediaSizeChange') mediaSize:MediaSize
  @Link @Watch('handleImage')  imageSources: Array<FileModel>

  @State currentImage: FileModel | undefined = undefined;
  @State isPreviewFailed: boolean = false;
  @State @Watch('loadCurrentPix')currentPixelMap: PixelMap | undefined = undefined;
  @State imageOrientation: number = PageDirection.VERTICAL;
  @State canvasWidth: number = 313 / canvasScale;
  @State canvasHeight: number = 444 / canvasScale;
  @State canvasRatio: number = 313 / 444;//width/height
  @State offCanvasWidth: number = this.canvasWidth * to300DPI * canvasScale;
  @State offCanvasHeight: number = this.canvasHeight * to300DPI * canvasScale;
  @State imageWidth: number = Constants.NUMBER_0;
  @State imageHeight: number = Constants.NUMBER_0;
  @State xPosition: number = Constants.NUMBER_0;
  @State yPosition: number = Constants.NUMBER_0;
  @State firstPageBackgroundColor: Resource = $r('app.color.effect_color_none');
  @State previousBackgroundColor: Resource = $r('app.color.effect_color_none');
  @State nextBackgroundColor: Resource = $r('app.color.effect_color_none');
  @State lastPageBackgroundColor: Resource = $r('app.color.effect_color_none');
  @State originalIndex: number = 1;
  private readonly maxWidth = 304
  private readonly maxHeight = 261
  @Link colorMode:number

  private rate: number = 1.5

  build() {
    Column() {
      Row() {
        Image($r('app.media.ic_firstPage')).width(32).height(32).key('PreviewComponent_Image_firstPage')
          .enabled(this.currentIndex !== 1 && !this.isGlobalDisable)
          .opacity((this.currentIndex !== 1 && !this.isGlobalDisable) ? Constants.NUMBER_1 : $r('app.float.disable_opacity'))
          .onClick(() => {
            this.currentIndex = 1;
            this.parseImageSize(false);
          })
          .borderRadius($r('app.float.radius_m'))
          .backgroundColor(this.firstPageBackgroundColor)
          .responseRegion({x:0,y:'-50%',width:'100%',height:'100%'})
          .onHover((isHover: boolean) => {
            if (isHover) {
              this.firstPageBackgroundColor =  $r('app.color.effect_color_hover')
            } else {
              this.firstPageBackgroundColor =  $r('app.color.effect_color_none')
            }
          })
          .onTouch((event: TouchEvent) => {
            if (event.type === TouchType.Down) {
              this.firstPageBackgroundColor =  $r('app.color.effect_color_press')
            }
            if (event.type === TouchType.Up) {
              this.firstPageBackgroundColor =  $r('app.color.effect_color_none')
            }

          })
        Image($r('app.media.ic_previous')).width(32).height(32).key('PreviewComponent_Image_previous')
          .enabled(this.currentIndex !== 1 && !this.isGlobalDisable)
          .opacity((this.currentIndex !== 1 && !this.isGlobalDisable) ? Constants.NUMBER_1 : $r('app.float.disable_opacity'))
          .onClick(() => {
            Log.info(TAG,'this.currentIndex --:'+this.currentIndex)
            if(this.currentIndex === 1) {
              return
            }
            this.currentIndex -= 1;
            this.parseImageSize(false);
          })
          .responseRegion({x:0,y:'-50%',width:'100%',height:'100%'})
          .borderRadius($r('app.float.radius_m'))
          .backgroundColor(this.previousBackgroundColor)
          .onHover((isHover: boolean) => {
            if (isHover) {
              this.previousBackgroundColor =  $r('app.color.effect_color_hover')
            } else {
              this.previousBackgroundColor =  $r('app.color.effect_color_none')
            }
          })
          .onTouch((event: TouchEvent) => {
            if (event.type === TouchType.Down) {
              this.previousBackgroundColor =  $r('app.color.effect_color_press')
            }
            if (event.type === TouchType.Up) {
              this.previousBackgroundColor =  $r('app.color.effect_color_none')
            }

          })
        Text(this.currentIndex+'/'+this.imageCount).key('PreviewComponent_Text_imageCount')
          .fontSize($r('app.float.font_size_body1'))
          .width($r('app.float.preview_pages_comp_width'))
          .height($r('app.float.params_comp_height')).textAlign(TextAlign.Center)
          .margin({left:$r('app.float.preview_pages_comp_margin_left'),right:$r('app.float.preview_pages_comp_margin_right')})
        Image($r('app.media.ic_next')).key('PreviewComponent_Image_next')
          .width(32)
          .height(32)
          .enabled(this.currentIndex !== this.imageCount && !this.isGlobalDisable)
          .opacity((this.currentIndex !== this.imageCount && !this.isGlobalDisable) ? Constants.NUMBER_1 : $r('app.float.disable_opacity'))
          .responseRegion({x:0,y:'-50%',width:'100%',height:'100%'})
          .onClick(() => {
            Log.info(TAG,'this.currentIndex --:'+this.currentIndex)
            if(this.currentIndex === this.imageCount) {
              return;
            }
            this.currentIndex += 1;
            this.parseImageSize(false);
          })
          .borderRadius($r('app.float.radius_m'))
          .backgroundColor(this.nextBackgroundColor)
          .onHover((isHover: boolean) => {
            if (isHover) {
              this.nextBackgroundColor =  $r('app.color.effect_color_hover')
            } else {
              this.nextBackgroundColor =  $r('app.color.effect_color_none')
            }
          })
          .onTouch((event: TouchEvent) => {
            if (event.type === TouchType.Down) {
              this.nextBackgroundColor =  $r('app.color.effect_color_press')
            }
            if (event.type === TouchType.Up) {
              this.nextBackgroundColor =  $r('app.color.effect_color_none')
            }

          })
        Image($r('app.media.ic_lastPage')).key('PreviewComponent_Image_lastPage')
          .width(32)
          .height(32)
          .enabled(this.currentIndex !== this.imageCount && !this.isGlobalDisable)
          .opacity((this.currentIndex !== this.imageCount && !this.isGlobalDisable) ? Constants.NUMBER_1 : $r('app.float.disable_opacity'))
          .onClick(() => {
            this.currentIndex = this.imageCount;
            this.parseImageSize(false)
          })
          .responseRegion({x:0,y:'-50%',width:'100%',height:'100%'})
          .borderRadius($r('app.float.radius_m'))
          .backgroundColor(this.lastPageBackgroundColor)
          .onHover((isHover: boolean) => {
            if (isHover) {
              this.lastPageBackgroundColor =  $r('app.color.effect_color_hover')
            } else {
              this.lastPageBackgroundColor =  $r('app.color.effect_color_none')
            }
          })
          .onTouch((event: TouchEvent) => {
            if (event.type === TouchType.Down) {
              this.lastPageBackgroundColor =  $r('app.color.effect_color_press')
            }
            if (event.type === TouchType.Up) {
              this.lastPageBackgroundColor =  $r('app.color.effect_color_none')
            }

          })
      }.height(48)
       .margin({top:8, bottom : 8})
      Row() {
        if (this.currentPixelMap) {
          Image(this.currentPixelMap).key('PreviewComponent_Image_currentPixelMap')
            .width(this.canvasWidth).height(this.canvasHeight)
            .backgroundColor($r('app.color.white'))
            .objectFit(this.isBorderless?ImageFit.Cover:ImageFit.Contain)
            .renderMode(this.colorMode === ColorCode.COLOR ? ImageRenderMode.Original : ImageRenderMode.Template)
            .shadow(ShadowStyle.OUTER_DEFAULT_MD)
        }else{
          Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
            Column(){
              if (CheckEmptyUtils.isEmptyArr(this.imageSources)) {
                Image($r('app.media.ic_gallery_list_damage')).fillColor('#66000000').width(36).height(36).margin({bottom:8})
                Text($r('app.string.preview_failed')).fontColor('#66000000').fontSize($r('app.float.font_size_body2'))
              }else{
                LoadingProgress().width(36).height(36).margin({bottom:8})
                Text( $r('app.string.preview_loading')).fontColor('#66000000').fontSize($r('app.float.font_size_body2'))
              }
            }
          }.width(this.canvasWidth).height(this.canvasHeight).backgroundColor($r('app.color.white'))
          .shadow({ radius: $r('app.float.radius_m'), color: Color.Gray, offsetX: Constants.NUMBER_0, offsetY: Constants.NUMBER_0 })
        }
      }
      .width(480)
      .height(this.previewCompHeight-80)
      .justifyContent(FlexAlign.Center)
      .alignItems(VerticalAlign.Center)
      .margin({bottom : $r('app.float.preview_comp_margin')})
    }
    .width($r('app.float.preview_comp_width'))
    .height(this.previewCompHeight)
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r('app.color.preview_background_color'))
  }

  aboutToAppear() {
    if(this.imageSources !== undefined){
      this.handleImage()
    }else{
      this.checkCanvasWidth()
    }
  }

  aboutToDisappear() {
  }

  parseImageSize(isRendered: boolean) {
    this.originalIndex = this.printRange[this.currentIndex - 1]
    this.currentImage = this.imageSources[this.originalIndex - 1];
    if (CheckEmptyUtils.isEmpty(this.currentImage)){
      return;
    }
    if (!isRendered) {
      this.fdToPixelMap(this.currentImage!.fd);
    }
    let width = this.currentImage!.width
    let height = this.currentImage!.height
    if(width > height) {
      this.imageOrientation = PageDirection.LANDSCAPE  //图片横向
    } else {
      this.imageOrientation = PageDirection.VERTICAL //图片竖向
    }
    this.updateCanvasSize()
  }

  updateCanvasSize() {
    if (this.pageDirection === PageDirection.AUTO) {
      if (this.imageOrientation === PageDirection.LANDSCAPE) {//图片横向
        this.setWidthMax()
      } else if (this.imageOrientation === PageDirection.VERTICAL) {//图片竖向
        this.setHeightMax()
      }
    } else if (this.pageDirection === PageDirection.LANDSCAPE) {
      //横向
      this.setWidthMax()
    } else if (this.pageDirection === PageDirection.VERTICAL) {
      //竖向
      this.setHeightMax()
    }
  }

  setWidthMax(){
    this.canvasWidth = this.maxWidth
    this.canvasHeight = this.canvasWidth * this.canvasRatio
  }

  setHeightMax(){
    this.canvasHeight = this.previewCompHeight-80
    this.canvasWidth = this.canvasHeight * this.canvasRatio
  }


  /**
   * 纸张尺寸修改事件
   */
  onMediaSizeChange() {
    let pixelSize = this.mediaSize.getPixelMediaSize()
    this.canvasWidth = pixelSize.width / this.rate
    this.canvasHeight = pixelSize.height / this.rate;
    this.canvasRatio  = pixelSize.width / pixelSize.height
    this.checkCanvasWidth()
    this.parseImageSize(true)
  }

  /**
   * 纸张方向修改
   */
  onPageDirectionChange() {
    Log.info(TAG, 'onPageDirectionChange enter');
    this.parseImageSize(true)
  }
  /**
   * 打印范围修改
   */
  onPrintRangeChange() {
    Log.info(TAG, 'onPrintRangeChange enter',JSON.stringify(this.printRange));
    if (this.printRange.length === 0 || this.imageSources === undefined) {
      return;
    }
    if (this.currentIndex>this.printRange.length) {
      Log.info(TAG, 'parseImageSize this.printRange.length: ', JSON.stringify(this.printRange.length))
      this.currentIndex = this.printRange.length
    }
    let newIndex = this.printRange[this.currentIndex - 1]
    Log.info(TAG,'newIndex: '+newIndex+' originalIndex: '+this.originalIndex)
    if (newIndex === this.originalIndex) {
      this.parseImageSize(true)
    } else {
      this.parseImageSize(false)
    }
  }

  /**
   *界面高度调整
   */
  onHeightLoad(){
    Log.info(TAG,'onHeightLoad:'+this.previewCompHeight)
    if (this.imageSources === undefined ){
      return;
    }
    if(this.previewCompHeight){
      this.handleImage();
    }
  }


  /**
   * 调整画布的方向
   */
  swapCanvasWidthAndHeight() {
    let temp = this.canvasWidth;
    this.canvasWidth = this.canvasHeight
    this.canvasHeight = temp
    this.checkCanvasWidth()
  }
  /**
   * 画布宽度是否超过最大值
   */
  checkCanvasWidth(){
    let ratio: number = 1;
    if(this.canvasWidth > Constants.CANVAS_MAX_WIDTH){
      ratio = this.canvasHeight/this.canvasWidth
      this.canvasWidth = Constants.CANVAS_MAX_WIDTH
      this.canvasHeight = this.canvasWidth * ratio
    }
    if(this.canvasHeight > Constants.CANVAS_MAX_HEIGHT){
      ratio = this.canvasWidth/this.canvasHeight
      this.canvasHeight = Constants.CANVAS_MAX_HEIGHT
      this.canvasWidth = this.canvasHeight * ratio
    }
  }
  /**
   * fd生成pixelMap
   * @param fd
   */
  fdToPixelMap(fd:number){
    Log.info(TAG, 'fd is: ' + fd);
    Log.debug(TAG, 'this.currentImage: ' + JSON.stringify(this.currentImage));
    if (this.currentImage === undefined) {
      Log.error(TAG, 'currentImage is undefined');
      return;
    }
    if (CheckEmptyUtils.isEmpty(this.currentImage!.imageSource)) {
      this.currentImage!.imageSource = image.createImageSource(fd);
      if (this.currentImage!.imageSource === undefined) {
        Log.error(TAG, 'createImageSource error');
        return;
      }
    }
    let info = this.currentImage!.imageSource!.getImageInfo();
    if (CheckEmptyUtils.isEmpty(info)) {
      Log.error(TAG, 'createImageSource error: invalid imageSource');
      return;
    }
    let decodingOptions: image.DecodingOptions | undefined = undefined;
    let width = this.currentImage!.width
    let height = this.currentImage!.height
    let ratio = width/height
    if(width*height>=Constants.MAX_PIXELMAP){//超过像素上限pixelmap无法显示在image组件里,需要resize
      height = Math.floor(Math.sqrt(Constants.MAX_PIXELMAP/ratio))
      Log.info(TAG,'decodingOptions width: '+height*ratio+' height: '+height)
      decodingOptions = {
        desiredSize:{width:height*ratio,height:height}
      }
    }
    this.currentImage!.imageSource!.createPixelMap(decodingOptions).then(pixelmap => {
      Log.info(TAG,'Succeeded in creating pixelmap object through image decoding parameters.');
      if(this.currentPixelMap!==undefined){
        this.currentPixelMap!.release().then(()=>{
          Log.info(TAG,'currentPixelMap release success');
          this.currentPixelMap = pixelmap
          GlobalThisHelper.createValue<PixelMap>(this.currentPixelMap, GlobalThisStorageKey.KEY_CURRENT_PIXELMAP);
        })
      }else{
        this.currentPixelMap = pixelmap
        GlobalThisHelper.createValue<PixelMap>(this.currentPixelMap, GlobalThisStorageKey.KEY_CURRENT_PIXELMAP);
      }

    }).catch((error: BusinessError) => {
      Log.info(TAG,'Failed to create pixelmap object through image decoding parameters.'+error);
    })
  }

  handleImage(){
    Log.info(TAG,'handleImage'+this.imageSources.length)
    this.checkCanvasWidth()
    this.parseImageSize(false);
  }

  loadCurrentPix(){
    if (this.currentPixelMap === undefined) {
      Log.info(TAG,'loadCurrentPix load failed')
    }else{
      Log.info(TAG,'loadCurrentPix load success')
    }
  }
}
