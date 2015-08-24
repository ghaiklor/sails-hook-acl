var _ = require('lodash');

module.exports = function (sails) {
  return {
    initialize: function (cb) {
      var acl = _getACL(sails.config.acl);
      console.log(acl);
      var authPolicyName = sails.config.acl.authPolicy || 'isAuthenticated';
      var aclPolicyFn = _.partial(_aclPolicy, acl);

      sails.on('hook:orm:loaded', function () {
        var policyMap = sails.hooks.policies.mapping;
        var injectPolicy = _.partial(_injectPolicy, authPolicyName, _, aclPolicyFn);
        _.forEach(policyMap, function (controllerPolicy) {
          if (_.isArray(controllerPolicy)) return injectPolicy(policyMap['*']); // inject policy for *;
          _.map(controllerPolicy, injectPolicy);
        });
      });

      cb();
    }
  }
};

function _injectPolicy(authPolicyName, actionPolicies, fn) {
  var eqFunc = _.ary(_.flow(_.partial(_.result, _, 'globalId'), _.partial(_.isEqual, authPolicyName)), 1);
  var authPolicyIndex = _.findIndex(actionPolicies, eqFunc);
  actionPolicies.splice(authPolicyIndex + 1, 0, fn);
}

function _aclPolicy(acl, req, res, next) {
  var currentRole = _.get(req, 'user.role') || 'guest';
  var controller = req.options.controller;
  var action = req.options.action;
  var check = _.partial(_.get, acl, _, false);
  if (check([currentRole, controller, action].join('.')) || check([currentRole, controller, '*'].join('.'))) {
    return next();
  }
  res.unauthorized();
}

function _createRoleHelpObj(obj) {
  return _.transform(obj, function (res, val, key) {
    if (key === 'inherits')
      return res[key] = val;
    res[key] = _.object(val, _.fill(new Array(val.length), true));
  });
}

/*
 * Returns full permissions object (with inherited permissions) for role
 */
function _getRolePermissions(defaultAcl, inheritedAcl, roleName) {
  if (roleName in inheritedAcl) return inheritedAcl[roleName];
  var rolePermissions = defaultAcl[roleName];
  var role = rolePermissions;
  if (rolePermissions.inherits) {
    role = _.merge(rolePermissions, _getRolePermissions(defaultAcl, inheritedAcl, rolePermissions.inherits), function (a, b) {
      if (_.isString(a)) a = [a];
      if (_.isString(b)) b = [b];
      if (_.isArray(a) && _.isArray(b)) return a;
    });
    delete role.inherits;
  }
  return inheritedAcl[roleName] = role;
}

function _getACL(aclConfig) {
  var fullACL = {};
  var getRolePermissionsFn = _.partial(_getRolePermissions, aclConfig.roles, fullACL);
  // apply inheritance
  _.forEach(aclConfig.roles, function (rolePermissions, roleName) {
    getRolePermissionsFn(roleName);
  });
  // create help obj
  return _.transform(fullACL, function (result, val, key) {
    result[key] = _createRoleHelpObj(val);
  });
}
