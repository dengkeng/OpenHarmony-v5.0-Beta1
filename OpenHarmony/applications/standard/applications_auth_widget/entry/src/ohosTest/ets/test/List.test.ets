/**
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

import ConstantsTest from './jsunit/Constants.test';
import FuncUtilsTest from './jsunit/FuncUtils.test';
import PageComTest from './jsunit/PageCom.test';
import FindWindowExampleTest from './uitest/FindWindowExample.test';
import PinNumberTest from './uitest/PinNumber.test';
import CustomPinTest from './uitest/CustomPin.test';
import CustomMixFailTest from './uitest/CustomMixFail.test';
import CustomMixFailTimesTest from './uitest/CustomMixFailTimes.test';
import CustomPasswordNumberTest from './uitest/CustomPasswordNumber.test';
import PinTest from './uitest/Pin.test';
import PinFailTimesTest from './uitest/PinFailTimes.test';
import FingerLock from './uitest/FingerLock.test';
import PinFaceTest from './uitest/PinFace.test';
import FaceTest from './uitest/Face.test';
import FaceFailTimesTest from './uitest/FaceFailTimes.test';
import FaceMixTimesAuthTest from './uitest/FaceMixAuth.test';
import PinFaceFailTest from './uitest/PinFaceFail.test';
import FaceMixFailAuthTest from './uitest/FaceMixFailAuth.test';
import FaceMixSuccessAllTest from './uitest/FaceMixSuccessAll.test';
import FaceMixFailAllTest from './uitest/FaceMixFailAll.test';
import FacePinFailTimesTest from './uitest/FacePinFailTimes.test';
import FaceFingerFailTimesTest from './uitest/FaceFingerFailTimes.test';
import FaceFingerFailTest from './uitest/FaceFingerFail.test';
import FaceMixSuccessLandscapeTest from './uitest/FaceMixSuccessLandscape.test';
import FingerTest from './uitest/finger.test';
import PinFingerTest from './uitest/PinFinger.test';
import FingerFailAuthTest from './uitest/FingerFailTimesAuth.test';
import PinFingerFailTest from './uitest/PinFingerFail.test';
import FingerUnderTest from './uitest/FingerUnder.test';
import PinFingerOnTest from './uitest/PinFingerOn.test';
import PinFingerUnderTest from './uitest/PinFingerUnder.test';
import FingerOnTest from './uitest/FingerOn.test';
import PinFingerOnFailTest from './uitest/PinFingerOnFail.test';
import PinFingerUnderFailTest from './uitest/PinFingerUnderFail.test';
import FingerOnNullTest from './uitest/FingerOnNull.test';
import FingerUnderNullTest from './uitest/FingerUnderNull.test';
import FingerOutBackTest from './uitest/FingerOutBack.test';
import FingerOutFrontTest from './uitest/FingerOutFront.test';
import FingerOutSideTest from './uitest/FingerOutSide.test';
import PinFingerOutBackTest from './uitest/PinFingerOutBack.test';
import PinFingerOutFrontTest from './uitest/PinFingerOutFront.test';
import PinFingerOutSideTest from './uitest/PinFingerOutSide.test';

export default function testsuite() {
  PageComTest();
  FuncUtilsTest();
  ConstantsTest();
  FindWindowExampleTest();
  FingerTest();
  PinFingerTest();
  FingerFailAuthTest();
  PinFingerFailTest();
  PinNumberTest();
  CustomPinTest();
  CustomMixFailTest();
  CustomMixFailTimesTest();
  CustomPasswordNumberTest();
  FaceTest();
  FaceFailTimesTest();
  FaceMixTimesAuthTest();
  PinTest();
  PinFailTimesTest();
  FingerLock();
  PinFaceTest();
  PinFaceFailTest();
  FaceMixFailAuthTest();
  FaceMixSuccessAllTest();
  FaceMixFailAllTest();
  FacePinFailTimesTest();
  FaceFingerFailTimesTest();
  FaceFingerFailTest();
  FaceMixSuccessLandscapeTest();
  FingerOnTest();
  FingerUnderTest();
  PinFingerOnTest();
  PinFingerUnderTest();
  PinFingerOnFailTest();
  PinFingerUnderFailTest();
  FingerOnNullTest();
  FingerUnderNullTest();
  FingerOutBackTest();
  FingerOutFrontTest();
  FingerOutSideTest();
  PinFingerOutBackTest();
  PinFingerOutFrontTest();
  PinFingerOutSideTest();
}