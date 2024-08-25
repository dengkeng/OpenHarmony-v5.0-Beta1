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
const { Farther, Cat, Bob, Juliya, Tom, TestMember } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");
const { consumers } = require("stream");

describe('Basic extends', function () {
    function getSkinCallback (skin) {
        assert.strictEqual(skin, '');
    }
    function getSkinAsyncCallback (err, skin) {
        assert.strictEqual(err.code, 0);
        assert.strictEqual(skin, '');
    }
    function getShoesCallback (shoes) {
        assert.strictEqual(shoes, '');
    }
    function getShoesAsyncCallback (err, shoes) {
        assert.strictEqual(err.code, 0);
        assert.strictEqual(shoes, '');
    }
    it('test interface extends', function () {
        let farther = new Farther();
        assert.strictEqual(farther.name, '');
        assert.strictEqual(farther.age, 0);
        assert.strictEqual(farther.getSkin(1), '');
        farther.getSkinSync(1, getSkinCallback);
        farther.getSkinAsync(1, getSkinAsyncCallback);
        assert.strictEqual(farther.getShoes(), '');
        farther.getShoesSync(getShoesCallback);
        farther.getShoesAsync(getShoesAsyncCallback);
    });

    it('test class extends', function () {
        let cat = new Cat();
        assert.strictEqual(cat.aniName, '');
        assert.strictEqual(cat.size, 0);
        assert.strictEqual(cat.catName, '');
        assert.strictEqual(cat.getAnimalType(1), '');
        assert.strictEqual(cat.setAnimalId(1), undefined);
        assert.strictEqual(cat.getCatType(1), '');
    });
});

describe('Multi extends', function () {
    it('test interface extends', function () {
        let bob = new Bob();
        assert.strictEqual(bob.name, '');
        assert.strictEqual(bob.aniName, '');
        assert.strictEqual(bob.bobSkill, '');
        assert.strictEqual(bob.getAnimalType(1), '');
        assert.strictEqual(bob.getBobCardId(), 0);
    });

    it('test extends and implements', function () {
        let juliya = new Juliya();
        assert.strictEqual(juliya.name, '');
        assert.strictEqual(juliya.aniName, '');
        assert.strictEqual(juliya.juliyaSkill, '');
        assert.strictEqual(juliya.getAnimalType(1), '');
        assert.strictEqual(juliya.getJuliyaCardId(), 0);
    });
});

describe('Function test1', function () {
    it('test parameter and return', function () {
        let juliya = new Juliya();
        let ret = test.findJuliya(juliya);
        // parent properties
        assert.strictEqual(ret.name, '');
        assert.strictEqual(ret.age, 0);
        // own properties
        assert.strictEqual(ret.aniName, '');
        assert.strictEqual(ret.size, 0);
        assert.strictEqual(ret.juliyaSkill, '');
    });
});

describe('Function test2', function () {   
    it('test sync callback', function () {
        function getSyncCallback (juliya) {
            // parent properties
            assert.strictEqual(juliya.name, '');
            assert.strictEqual(juliya.age, 0);
            // own properties
            assert.strictEqual(juliya.aniName, '');
            assert.strictEqual(juliya.size, 0);
            assert.strictEqual(juliya.juliyaSkill, '');
        }

        test.findJuliyaSync("juli", getSyncCallback);
    });
    
    it('test async callback', function () {
        function getAsyncCallback (err, juliya) {
            assert.strictEqual(err.code, 0);
            // parent properties
            assert.strictEqual(juliya.name, '');
            assert.strictEqual(juliya.age, 0);
            // own properties
            assert.strictEqual(juliya.aniName, '');
            assert.strictEqual(juliya.size, 0);
            assert.strictEqual(juliya.juliyaSkill, '');
        }

        test.findJuliyaAsync("juli", getAsyncCallback);
    });
    
});

describe('Interface member test', function () {
    it('test member', function () {        
        let tomObj1 = {
            name: 'tom1',
            friends: { // Cat object
                catName: 'tomcat1',
                aniName: 'ani1',
                size: 101                
            }
        };
        let tomObj2 = {
            name: 'tom2',
            friends: { // Cat object
                catName: 'tomcat1',
                aniName: 'ani2',
                size: 102                
            }
        };
        let tomArray = [tomObj1, tomObj2];
        let test = new TestMember();
        let retTom = test.getTomcat('my tom', tomArray);
        assert.strictEqual(retTom.name, '');
        // class member
        assert.strictEqual(retTom.friends.catName, '');
        assert.strictEqual(retTom.friends.aniName, '');
        assert.strictEqual(retTom.friends.size, 0);
    });
    
});



