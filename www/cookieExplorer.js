/**
 * CookieEmperor
 * @constructor
 */
function CookieExplorer(pluginName) {
    this.version = 1;
    this.pluginName = pluginName;
}

/**
 * returns cookie value
 * @param url
 * @param cookieName
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.getCookie = function(url, cookieName, successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback, this.pluginName, 'getCookieValue', [url, cookieName]);
};

/**
 * sets cookie
 * @param url
 * @param cookieName
 * @param cookieValue
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.setCookie = function (url, cookieName, cookieValue, successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback,  this.pluginName, 'setCookieValue', [url, cookieName, cookieValue]);
};

/**
 * clears all cookies
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.prepareCookieManagement = function(successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback,  this.pluginName, 'prepareCookieManagement', []);
};

/**
 * clears all cookies
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.clearSessionCookies = function(successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback,  this.pluginName, 'clearSessionCookies', []);
};

/**
 * clears all cookies
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.getMCookie = function(successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback,  this.pluginName, 'getMCookie', []);
};

/**
 * clears all cookies
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.setMCookie = function(successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback,  this.pluginName, 'setMCookie', []);
};

/**
 * clears all cookies
 * @param successCallback
 * @param errorCallback
 */
CookieExplorer.prototype.clearMCookie = function(successCallback, errorCallback) {
    cordova.exec(successCallback, errorCallback,  this.pluginName, 'clearMCookie', []);
};


/**
 * export default CookieExplorer
 * @type {CookieExplorer}
 */
module.exports = new CookieExplorer('CookieExplorer');
