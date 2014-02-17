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

var url = require('url');

var OPENID_NS = 'http://specs.openid.net/auth/2.0';  // TODO duplicated

exports.fromBody = function(req) {
    return parse(req.body);   // TODO assumes express.urlencoded middleware is in place
}

exports.fromQueryArgs = function(req) {
    var query = url.parse(req.url, true).query;

    return parse(query);
}

exports.toForm = function(obj, fields) {
    // NOTE: The placement of \n in the output is important. In particular, the output needs to
    // end in \n or else the signature won't be valid

    // 4.1.1
    var result = {
        body: '',
        fields: []
    }

    obj.ns = OPENID_NS;  // 5.1.2

    if (fields) {
        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            result.fields.push(field);
            result.body = result.body + field + ':' + obj[field] + '\n';
        };
    } else {
        for (var field in obj) {
            result.fields.push(field);
            result.body = result.body + field + ':' + obj[field] + '\n';
        }
    }

    return result;
}

exports.getExtension = function(obj, extensionNamespace) {
    for (var field in obj) {
        if (field.slice(0, 3) === 'ns.' && obj[field] === extensionNamespace) {
            var namespaceAlias = field.substr(3);
            return parseExtension(obj, namespaceAlias);
        }
    }

    return null;
}

function parseExtension(obj, namespaceAlias) {
    var prefix = namespaceAlias + '.',
        result = {
            alias: namespaceAlias,
            fields: {}
        };

    for (var field in obj) {
        if (field.slice(0, prefix.length) === prefix) {
            result.fields[field.substr(prefix.length)] = obj[field];
        }
    }

    return result;
}

function parse(obj) {
    var message = {}

    for (var opt in obj) {
        if (opt.indexOf('openid.') == 0) {
            var key = opt.substr(7).toLowerCase();

            message[key] = obj[opt];
        }
    }

    return message;
}
