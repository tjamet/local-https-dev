const fetch = require('node-fetch');
const atob = require('atob');

function getCertificate(host, domain){
    return new Promise(function(resolve, reject){
        fetch(host+"/json/"+domain)
        .then(response => {
          response.json()
          .then(json => resolve(json))
          .catch(error=>reject(error));
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
