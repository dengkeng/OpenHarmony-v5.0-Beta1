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
import { AsyncCallback, Callback } from './../basic';

declare namespace napitest {
    interface Human {
        name: string;
        age: number;
    }

    interface GrandFar extends Human{
        eyesType: number;
        getSkin(v: number): string;
        getSkinSync(v: number, skin: Callback<string>): void;
        getSkinAsync(v: number, skin: AsyncCallback<string>): void;
    }

    interface Farther extends GrandFar {
        getShoes(): string;
        getShoesSync(shoes: Callback<string>): void;
        getShoesAsync(shoes: AsyncCallback<string>): void;
    }

    class Animal {
        aniName: string;
        size: number;
        static getAnimalType(aniId: number): string;
        setAnimalId(id: number): void;
    }

    class Cat extends Animal {
        catName:string;
        static getCatType(catId: number): string;
    }
    
    interface SuperAnimal {
        aniName: string;
        size: number;
        setAnimalId(id: number): void;
    }
    
    class SuperHuman {
        name: string;
        age: number;
        static getAnimalType(aniId: number): string;
    }
    
    interface Bob extends Human, Animal {
        bobSkill: string;
        getBobCardId(): number;
    }

    class Juliya extends SuperHuman implements SuperAnimal {
        aniName: string;
        size: number;
        setAnimalId(id: number): void;
        juliyaSkill: string;
        getJuliyaCardId(): number;
    }

    function findJuliya(v1: Juliya): Juliya;
    function findJuliyaSync(v1: string, callback: Callback<Juliya>): void;
    function findJuliyaAsync(v1: string, callback: AsyncCallback<Juliya>): void;
    
    interface Tom {
        name: string;
        friends: Cat;
    }

    interface TestMember {
        getTomcat(v1: string, v2: Array<Tom>): Tom;
    }
}

export default napitest;
