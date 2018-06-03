const fetch = require('node-fetch');
const atob = require('atob');
const btoa = require('btoa');
const netrc = require('netrc');
const url = require('url');

function getCertificate(host, domain){
    var headers = {};
    if (domain==nil) {
        domain = "www.local.xtls.io";
    }
    if (host==nil) {
        host = "https://api.xtls.io";
    }

    const myNetrc = netrc();
    hostname = new url.URL(host).hostname;
    if (myNetrc[hostname] != null) {
        var auth = "";
        if (myNetrc[hostname].user){
            auth += myNetrc[hostname].user;
        }
        auth += ":";
        if (myNetrc[hostname].password){
            auth += myNetrc[hostname].password;
        }
        headers.Authorization = "Basic " + btoa(auth);
    }

    return new Promise(function(resolve, reject){
        fetch(host+"/json/"+domain, {headers})
        .then(response => {
            if (response.status != 200){
                reject("Failed to get certificate, unexpected status: " + response.status)
            } else {
                response.json()
                .then(json => resolve(json))
                .catch(error=>reject(error));
          }
        })
        .catch(error => {
          reject(error);
        });
    });
};

exports.webpackConfigSetter = function(webpackConfig, certificateProviderHost, domain){
    return new Promise(function(resolve, reject){
        getCertificate(certificateProviderHost, domain)
        .then(cert=>{
            if (webpackConfig.devServer == null) {
                webpackConfig.devServer = {};
            }
            webpackConfig.devServer.https=true;
            if (cert["issuer-certificate"] != null) {
                webpackConfig.devServer.ca = atob(cert["issuer-certificate"]);
            }
            if (cert["certificate"] != null) {
                webpackConfig.devServer.cert = atob(cert["certificate"]);
            }
            if (cert["private-key"] != null) {
                webpackConfig.devServer.key = atob(cert["private-key"]);
            }
            resolve(webpackConfig);
        })
        .catch(error=>reject(error));
    });
}
exports.getCertificate = getCertificate;
