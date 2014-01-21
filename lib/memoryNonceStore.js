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

// TODO: periodically clean up expired nonces

function MemoryNonceStore() {
    if (!(this instanceof MemoryNonceStore)) {
        return new MemoryNonceStore();
    }

    var nonces = {};

    this.put = function(nonce, next) {
        console.log('Stored nonce', nonce);
        nonces[nonce.id] = nonce;
        next(null);
    }

    this.getAndDelete = function(id, next) {
        console.log('Fetching & deleting nonce', id);
        var nonce = nonces[id];
        delete nonces[id];
        next(null, nonce);
    }
}

exports = module.exports = MemoryNonceStore;
