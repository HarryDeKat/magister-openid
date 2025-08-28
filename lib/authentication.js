"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.AuthProvider = void 0;
var _regenerator = _interopRequireDefault(require("@babel/runtime/regenerator"));
var _toConsumableArray2 = _interopRequireDefault(require("@babel/runtime/helpers/toConsumableArray"));
var _asyncToGenerator2 = _interopRequireDefault(require("@babel/runtime/helpers/asyncToGenerator"));
var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));
var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));
var _nodeFetch = _interopRequireDefault(require("node-fetch"));
var _openidClient = require("openid-client");
var _common = require("./utils/common");
var AuthProvider = exports.AuthProvider = /*#__PURE__*/function () {
  function AuthProvider(tenant) {
    (0, _classCallCheck2["default"])(this, AuthProvider);
    this.tenant = tenant;
    this.client = null;
    this.codeVerifier = _openidClient.generators.codeVerifier();
    this.state = _openidClient.generators.state();
    this.nonce = _openidClient.generators.nonce();
  }
  return (0, _createClass2["default"])(AuthProvider, [{
    key: "validate",
    value: function () {
      var _validate = (0, _asyncToGenerator2["default"])(/*#__PURE__*/_regenerator["default"].mark(function _callee(response) {
        var code, data;
        return _regenerator["default"].wrap(function (_context) {
          while (1) switch (_context.prev = _context.next) {
            case 0:
              code = response.status;
              if (!(code === 200)) {
                _context.next = 1;
                break;
              }
              return _context.abrupt("return");
            case 1:
              _context.next = 2;
              return response.json();
            case 2:
              data = _context.sent;
              throw new Error(data.error || code);
            case 3:
            case "end":
              return _context.stop();
          }
        }, _callee);
      }));
      function validate(_x) {
        return _validate.apply(this, arguments);
      }
      return validate;
    }()
  }, {
    key: "refreshTokenSet",
    value: function refreshTokenSet(refreshToken) {
      return this.client.refresh(refreshToken);
    }
  }, {
    key: "getTokenSet",
    value: function getTokenSet(code) {
      return this.client.callback("m6loapp://oauth2redirect/", {
        code: code
      }, {
        code_verifier: this.codeVerifier,
        nonce: this.nonce
      }, {
        exchangeBody: {
          client_id: "M6LOAPP",
          headers: {}
        }
      });
    }
  }, {
    key: "getCode",
    value: function () {
      var _getCode = (0, _asyncToGenerator2["default"])(/*#__PURE__*/_regenerator["default"].mark(function _callee3(username, password, authCode) {
        var _this = this;
        var issuerUrl, issuer, codeChallenge, authUrl, noRedirects, authResponse, location, sessionId, returnUrl, cookies, xsrfCookie, xsrfToken, authCookies;
        return _regenerator["default"].wrap(function (_context3) {
          while (1) switch (_context3.prev = _context3.next) {
            case 0:
              issuerUrl = "https://accounts.magister.net";
              _context3.next = 1;
              return _openidClient.Issuer.discover(issuerUrl);
            case 1:
              issuer = _context3.sent;
              codeChallenge = _openidClient.generators.codeChallenge(this.codeVerifier);
              this.client = new issuer.Client({
                authority: issuerUrl,
                client_id: "M6LOAPP",
                redirect_uris: ["m6loapp://oauth2redirect/"],
                response_types: ["code id_token"],
                id_token_signed_response_alg: "RS256",
                token_endpoint_auth_method: "none"
              });
              this.client[_openidClient.custom.clock_tolerance] = 5;
              authUrl = this.client.authorizationUrl({
                scope: "openid profile offline_access",
                code_challenge: codeChallenge,
                code_challenge_method: "S256",
                acr_values: "tenant:".concat(this.tenant),
                client_id: "M6LOAPP",
                state: this.state,
                nonce: this.nonce,
                prompt: "select_account"
              });
              noRedirects = {
                redirect: "manual",
                follow: 0
              };
              _context3.next = 2;
              return (0, _nodeFetch["default"])(authUrl, noRedirects).then(function (response) {
                return (0, _nodeFetch["default"])(response.headers.get("location"), noRedirects);
              });
            case 2:
              authResponse = _context3.sent;
              location = authResponse.headers.get("location");
              sessionId = (0, _common.extractQueryParameter)("".concat(issuerUrl).concat(location), "sessionId");
              returnUrl = (0, _common.extractQueryParameter)("".concat(issuerUrl).concat(location), "returnUrl");
              cookies = authResponse.headers.raw()["set-cookie"];
              xsrfCookie = cookies.filter(function (cookie) {
                return cookie.split("=")[0] === "XSRF-TOKEN";
              })[0];
              xsrfToken = xsrfCookie.split("=")[1].split(";")[0];
              _context3.next = 3;
              return (0, _nodeFetch["default"])("".concat(issuerUrl, "/challenges/username"), {
                method: "post",
                body: JSON.stringify({
                  authCode: authCode,
                  sessionId: sessionId,
                  returnUrl: returnUrl,
                  username: username
                }),
                headers: {
                  "Content-Type": "application/json",
                  cookie: cookies.join('; '),
                  "X-XSRF-TOKEN": xsrfToken
                }
              }).then(this.validate);
            case 3:
              _context3.next = 4;
              return (0, _nodeFetch["default"])("".concat(issuerUrl, "/challenges/password"), {
                method: "post",
                body: JSON.stringify({
                  authCode: authCode,
                  sessionId: sessionId,
                  returnUrl: returnUrl,
                  password: password
                }),
                headers: {
                  "Content-Type": "application/json",
                  cookie: cookies.join('; '),
                  "X-XSRF-TOKEN": xsrfToken
                }
              }).then(/*#__PURE__*/function () {
                var _ref = (0, _asyncToGenerator2["default"])(/*#__PURE__*/_regenerator["default"].mark(function _callee2(response) {
                  return _regenerator["default"].wrap(function (_context2) {
                    while (1) switch (_context2.prev = _context2.next) {
                      case 0:
                        _context2.next = 1;
                        return _this.validate(response);
                      case 1:
                        return _context2.abrupt("return", response.headers.raw()["set-cookie"]);
                      case 2:
                      case "end":
                        return _context2.stop();
                    }
                  }, _callee2);
                }));
                return function (_x5) {
                  return _ref.apply(this, arguments);
                };
              }());
            case 4:
              authCookies = _context3.sent;
              return _context3.abrupt("return", (0, _nodeFetch["default"])("".concat(issuerUrl).concat(returnUrl), {
                redirect: "manual",
                follow: 0,
                headers: {
                  cookie: [].concat((0, _toConsumableArray2["default"])(cookies), (0, _toConsumableArray2["default"])(authCookies)).join('; ')
                }
              }).then(function (response) {
                var url = response.headers.get("location");
                return url.split("#code=")[1].split("&")[0];
              }));
            case 5:
            case "end":
              return _context3.stop();
          }
        }, _callee3, this);
      }));
      function getCode(_x2, _x3, _x4) {
        return _getCode.apply(this, arguments);
      }
      return getCode;
    }()
  }]);
}();