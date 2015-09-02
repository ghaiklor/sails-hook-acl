var acl = require('acl');
var mongo = require('mongodb');
var Promise = require('bluebird');

var aclHook = function (sails) {
  return {

    initialize: function (cb) {
      var params = 'mongodb://' + sails.config.connections.mongo.host + ':' + sails.config.connections.mongo.port + '/acl';

      mongo.connect(params)
        .then(function (connection) {
          // init acl
          acl = new acl(new acl.mongodbBackend(connection, 'acl_'));

          // set rules
          acl.allow(sails.config.acl.rules);

          // expose acl
          this.sails.hooks.acl = acl;

          cb();
        })
        .catch(console.log);
    }
  }
};

module.exports = aclHook;
