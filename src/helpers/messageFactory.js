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

const url = require('url');

// TODO duplicated
const OPENID_NS = 'http://specs.openid.net/auth/2.0';

const parse = (obj) => {
  const message = {};

  for (const opt in obj) {
    if (opt.startsWith('openid.')) {
      const key = opt.substr(7).toLowerCase();

      message[key] = obj[opt];
    }
  }

  return message;
};

// TODO assumes express.urlencoded middleware is in place
const fromBody = (req) => parse(req.body);

const fromQueryArgs = (req) => {
  const query = url.parse(req.url, true).query;

  return parse(query);
};

const toForm = (obj, fields) => {
  // NOTE: The placement of \n in the output is important. In particular, the output needs to
  // end in \n or else the signature won't be valid
  obj.ns = OPENID_NS;

  // 4.1.1
  const result = {
    body: '',
    fields: []
  };
  const formFields = fields ? fields : Object.keys(obj);

  for (const field of formFields) {
    result.fields.push(field);
    result.body = result.body + field + ':' + obj[field] + '\n';
  }

  return result;
};

const parseExtension = (obj, namespaceAlias) => {
  const prefix = namespaceAlias + '.';
  const result = {
    alias: namespaceAlias,
    fields: {}
  };

  for (const field in obj) {
    if (field.slice(0, prefix.length) === prefix) {
      result.fields[field.substr(prefix.length)] = obj[field];
    }
  }

  return result;
};

const getExtension = (obj, extensionNamespace) => {
  for (const field in obj) {
    if (field.slice(0, 3) === 'ns.' && obj[field] === extensionNamespace) {
      const namespaceAlias = field.substr(3);

      return parseExtension(obj, namespaceAlias);
    }
  }

  return null;
};

module.exports = {
  fromBody,
  fromQueryArgs,
  getExtension,
  parseExtension,
  toForm
};
