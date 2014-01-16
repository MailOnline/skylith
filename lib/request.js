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

function Request(req) {
    if (!(this instanceof Request)) {
        return new Request(req);
    }

    for (var opt in req.body) {
        if (opt.indexOf('openid.') == 0) {
            var key = opt.substr(7).toLowerCase();

            Object.defineProperty(this, key, {
                value: req.body[opt],
                configurable: false,
                writable: false,
                enumerable: true
            });
        }
    }

    this.httpReq = function() {
        return req;
    }
}

exports = module.exports = Request;
