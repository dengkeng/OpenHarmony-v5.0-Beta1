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

export enum MediaTypeCode {
	MEDIA_PLAIN,
	MEDIA_SPECIAL,
	MEDIA_PHOTO,
	MEDIA_TRANSPARENCY,
	MEDIA_IRON_ON,
	MEDIA_IRON_ON_MIRROR,
	MEDIA_ADVANCED_PHOTO,
	MEDIA_FAST_TRANSPARENCY,
	MEDIA_BROCHURE_GLOSSY,
	MEDIA_BROCHURE_MATTE,
	MEDIA_PHOTO_GLOSSY,
	MEDIA_PHOTO_MATTE,
	MEDIA_PREMIUM_PHOTO,
	MEDIA_OTHER_PHOTO,
	MEDIA_PRINTABLE_CD,
	MEDIA_PREMIUM_PRESENTATION,

	MEDIA_AUTO = 98,
	MEDIA_UNKNOWN = 99
}

export class MediaTypes {
	public static readonly sCodeToStringMap: Map<number, string> = new Map([
		[MediaTypeCode.MEDIA_PLAIN, 'stationery'],
		[MediaTypeCode.MEDIA_PHOTO, 'photographic'],
		[MediaTypeCode.MEDIA_TRANSPARENCY, 'transparency'],
		[MediaTypeCode.MEDIA_PHOTO_GLOSSY, 'photographic-glossy'],
		[MediaTypeCode.MEDIA_PHOTO_MATTE, 'photographic-matte'],
		[MediaTypeCode.MEDIA_AUTO, 'auto'],
	]);
}