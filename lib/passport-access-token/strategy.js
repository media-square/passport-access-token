"use strict";
const passport = require('passport')
    , util = require('util')
    , BadRequestError = require('./errors/badrequesterror')
;

const defaultOptions = {

};


function Strategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    if (!verify) {
        throw new Error('access token authentication strategy requires a verify function');
    }

    passport.Strategy.call(this);
    this.name = 'accesstoken';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}


/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
    options = options || {};
    const accessToken = getAccessTokenFromRequest(req);

    if (!accessToken) {
        return this.fail(new BadRequestError('No Access Token Provided'), 400);
    }

    let verified = function (err, accessToken, info) {
        if (err) { return this.error(err); }
        if (!accessToken) { return this.fail(info); }
        this.success(accessToken, info);
    }.bind(this);

    try {
        if (this._passReqToCallback) {
            this._verify(req, accessToken, verified);
        } else {
            this._verify(accessToken, verified);
        }
    } catch (Error) {
        return this.error(Error);
    }

    function getAccessTokenFromRequest(req){
        let accessToken = false;
        if(req.query['access-token']){
            accessToken = req.query['access-token'];
        }
        return accessToken;
    }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
