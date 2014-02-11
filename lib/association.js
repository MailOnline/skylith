// Copyright 2013-2014 Danny Yates

//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at

//        http://www.apache.org/licenses/LICENSE-2.0

//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

var crypto = require('crypto');

function Association(algorithm, secret, expirySecs, private) {
    if (!(this instanceof Association)) {
        return new Association(algorithm, secret, expirySecs, private);
    }

    define(this, 'handle', crypto.randomBytes(64).toString('base64'));
    define(this, 'algorithm', algorithm);
    define(this, 'secret', secret);
    define(this, 'expiry', Date.now() + (expirySecs * 1000));
    define(this, 'private', private);

    function define(obj, property, value) {
        Object.defineProperty(obj, property, {
            value: value,
            configurable: false,
            writable: false,
            enumerable: true
        });
    }
}

exports = module.exports = Association;
