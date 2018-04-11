# Local development using https

A pair of daemons and libraries to help providing valid HTTPS certificate during development phases.

# Motivation

In modern web, the use of HTTPS is recommended, and HTTP is on its way to
[deprecation](https://blog.mozilla.org/security/2015/04/30/deprecating-non-secure-http/).

With the increased security of HTTPS, comes a series of security techniques to increase
the overall web security such as:
- HTTP Strict Transport Security [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- Blocking [mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content/How_to_fix_website_with_mixed_content)
- [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [Referer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

These features can introduce a different behaviour between production over HTTPS and
local development over HTTP where some security features are ignored.
Such a difference can break a working feature during development phases once deployed to production.

## System description

### Certificate server

This server needs to be deployed on a _private_ network, available, for example via VPN, to the eligible developers.
This server is provided a zone configured to resolve `127.0.0.01` for any sub domain, and will only serve the certificates for this zone.
This server caches the certificates to reduce Let's Encrypt usage and keep as much as possible under the rate limits.

### Local proxy

This is an HTTP proxy that receives the certificate from the server and proxies all requests to a selected backend.
This proxy implements the same `X-Forwarded-For` header as described by amazon [ELB documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html)

### Javascript library

This library retrieves the certificate from the server and provides it to the node server.

## Usage

1. Create a DNS zone (such as local.example.com) is configured to always resolve 127.0.0.1
2. Get DNS provider API keys, and export them depending on your provider
3. Deploy the server on your _private_ network
```
docker run -d --name local-https-dev-server tjamet/local-https-dev-server --accept-tos --email <yourEmail> --dns <DNSProvider>  --domain local.example.com
```
  - `--accept-tos` instructs to accept Let's Encrypt Terms Of Service
  - `--email` the account email used to retrieve of create a let's encrypt account
  - `--dns` specifies the DNS provider to use (see [Supported DNS providers](#supported-dns-providers) for more details)
  - `--domain` specifies the zone setup to resolve 127.0.0.1 When provided, all certificate domain must be within this zone
4. Run either the local proxy or configure your javascript library

### Server help

```
NAME:
   local-https-dev-server - A simple HTTP server to serve certificates

USAGE:
   main [global options] command [command options] [arguments...]

VERSION:
   0.0.0

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --domain value, -d value  Specify the allowed domain suffix
   --server value, -s value  CA hostname (and optionally :port). The server certificate must be trusted in order to avoid further modifications to the client. (default: "https://acme-v02.api.letsencrypt.org/directory")
   --email value, -m value   Email used for registration and recovery contact.
   --dns value               Solve a DNS challenge using the specified provider.
   --path value              Directory where to store cache (let's encrypt account and certificates). (default: "~/.dev-acme")
   --accept-tos, -a          By setting this flag to true you indicate that you accept the current Let's Encrypt terms of service.
   --port value, -p value    The port the server should listen to. (default: 8080)
   --help, -h                show help
   --version, -v             print the version
```

## Using local proxy

The local proxy is written in go and can be run either within a container or locally.

### Install

To install the proxy, do to the [releases page](https://github.com/tjamet/local-https-dev/releases) and download the release
that matches your system.

### Run

Run the proxy in a container using the following command:
```
docker run -d --name local-https-dev-proxy tjamet/local-https-dev-proxy --server http://<ServerIP>:<ServerPort> --backend http://<YourBackendHost>:<YourBackendPort> --domain <subdomain>.local.example.com
```

### proxy help

```
NAME:
   local-https-dev-proxy - A proxy to handle HTTP TLS for localhost domains

USAGE:
   main [global options] command [command options] [arguments...]

VERSION:
   0.0.0

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --domain value, -d value   Add a domain to serve TLS on
   --server value, -s value   The server serving TLS certificates over HTTP
   --backend value, -b value  The backend to serve requests from
   --listen value, -l value   The port to listen on without TLS
   --tls value, -t value      The TLS port to listen on (default: 0.0.0.0:443 when no listen port is provided)
   --help, -h                 show help
   --version, -v              print the version
```

## Using javascript library

The library is available on npm as `local-https-dev` and can be installed by:
```
npm install --save-dev local-https-dev
```

It exports 2 functions:
- `getCertificate(server, domain)`: retrieve a Promise for the certificate `issuer-certificate`, `certificate` and `private-key`
- `webpackConfigSetter(webpackConfig, certificateProviderHost, domain)`: retrieve a Promise that sets the Webpack configuration

### Using webpack configuration

Edit your `webpack.config.js` and change the standard `module.exports = webpackConfig;` for
```
# in case you are running webpack as a standard user you might need to add this property to allow serving from <domain>.local.example.com
webpackConfig.devServer.disableHostCheck= true
module.exports = require('local-https-dev').webpackConfigSetter(webpackConfig, '<serverURL>', '<domain>.local.example.com')
```

### Using certificate promise

```
require('local-https-dev').getCertificate('<serverURL>', '<domain>.local.example.com')
        .then(cert=>{
            if (cert["issuer-certificate"] != null) {
                # setup issuer certificate
            }
            if (cert["certificate"] != null) {
                # setup cetificate
            }
            if (cert["private-key"] != null) {
                # setup private key
            }
        })
```


# Supported DNS Providers

local-https-dev is using [lego](https://github.com/xenolf/lego) Let's Encrypt client, as [caddy](https://github.com/mholt/caddy)
and [traefik](https://github.com/containous/traefik) does. lego supports several DNS providers as defined in caddy documentation:

<table>
    <tbody>
        <tr>
            <th>Provider</th>
            <th>Name to use on command line</th>
            <th>Environment Variables to Set</th>
        </tr>
        <tr>
            <td>Aurora DNS by PCExtreme</td>
            <td>auroradns</td>
            <td>AURORA_USER_ID<br>AURORA_KEY<br>AURORA_ENDPOINT (optional)</td>
        </tr>
        <tr>
            <td>Azure DNS</td>
            <td>azure</td>
            <td>AZURE_CLIENT_ID<br>AZURE_CLIENT_SECRET<br>AZURE_SUBSCRIPTION_ID<br>AZURE_TENANT_ID</td>
        </tr>
        <tr>
            <td>Cloudflare</td>
            <td>cloudflare</td>
            <td>CLOUDFLARE_EMAIL<br>CLOUDFLARE_API_KEY</td>
        </tr>
        <tr>
            <td>CloudXNS</td>
            <td>cloudxns</td>
            <td>CLOUDXNS_API_KEY<br>CLOUDXNS_SECRET_KEY</td>
        </tr>
        <tr>
            <td>DigitalOcean</td>
            <td>digitalocean</td>
            <td>DO_AUTH_TOKEN</td>
        </tr>
        <tr>
            <td>DNSimple</td>
            <td>dnsimple</td>
            <td>DNSIMPLE_EMAIL<br>DNSIMPLE_OAUTH_TOKEN</td>
        </tr>
        <tr>
            <td>DNS Made Easy</td>
            <td>dnsmadeeasy</td>
            <td>DNSMADEEASY_API_KEY<br>DNSMADEEASY_API_SECRET<br>DNSMADEEASY_SANDBOX (true/false)</td>
        </tr>
        <tr>
            <td>DNSPod</td>
            <td>dnspod</td>
            <td>DNSPOD_API_KEY</td>
        </tr>
        <tr>
            <td>DynDNS</td>
            <td>dyn</td>
            <td>DYN_CUSTOMER_NAME<br>DYN_USER_NAME<br>DYN_PASSWORD</td>
        </tr>
        <tr>
            <td>Gandi</td>
            <td>gandi / gandiv5</td>
            <td>GANDI_API_KEY / GANDIV5_API_KEY</td>
        </tr>
        <tr>
            <td>GoDaddy</td>
            <td>godaddy</td>
            <td>GODADDY_API_KEY<br>GODADDY_API_SECRET</td>
        </tr>
        <tr>
            <td>Google Cloud DNS</td>
            <td>googlecloud</td>
            <td>GCE_PROJECT<br>GCE_DOMAIN<br>GOOGLE_APPLICATION_CREDENTIALS<br>(or GCE_SERVICE_ACCOUNT_FILE)</td>
        </tr>
        <tr>
            <td>Lightsail by AWS</td>
            <td>lightsail</td>
            <td>AWS_ACCESS_KEY_ID<br>AWS_SECRET_ACCESS_KEY<br>AWS_SESSION_TOKEN (optional)<br>DNS_ZONE (optional)</td>
        </tr>
        <tr>
            <td>Linode</td>
            <td>linode</td>
            <td>LINODE_API_KEY</td>
        </tr>
        <tr>
            <td>Namecheap</td>
            <td>namecheap</td>
            <td>NAMECHEAP_API_USER<br>NAMECHEAP_API_KEY</td>
        </tr>
        <tr>
            <td>NS1.</td>
            <td>ns1</td>
            <td>NS1_API_KEY</td>
        </tr>
        <tr>
            <td>Name.com</td>
            <td>namedotcom</td>
            <td>NAMECOM_USERNAME<br>NAMECOM_API_TOKEN</td>
        </tr>
        <tr>
            <td>OVH</td>
            <td>ovh</td>
            <td>OVH_ENDPOINT<br>OVH_APPLICATION_KEY<br>OVH_APPLICATION_SECRET<br>OVH_CONSUMER_KEY</td>
        </tr>
        <tr>
            <td>Open Telekom Cloud<br>Managed DNS</td>
            <td>otc</td>
            <td>OTC_DOMAIN_NAME<br>OTC_USER_NAME<br>OTC_PASSWORD<br>OTC_PROJECT_NAME<br>OTC_IDENTITY_ENDPOINT (optional)</td>
        </tr>
        <tr>
            <td>PowerDNS</td>
            <td>pdns</td>
            <td>PDNS_API_URL<br>PDNS_API_KEY</td>
        </tr>
        <tr>
            <td>Rackspace</td>
            <td>rackspace</td>
            <td>RACKSPACE_USER<br>RACKSPACE_API_KEY</td>
        </tr>
        <tr>
            <td></td>
            <td>rfc2136</td>
            <td>RFC2136_NAMESERVER<br>RFC2136_TSIG_ALGORITHM<br>RFC2136_TSIG_KEY<br>RFC2136_TSIG_SECRET</td>
        </tr>
        <tr>
            <td>Route53 by AWS</td>
            <td>route53</td>
            <td>AWS_ACCESS_KEY_ID<br>AWS_SECRET_ACCESS_KEY</td>
        </tr>
        <tr>
            <td>Vultr</td>
            <td>vultr</td>
            <td>VULTR_API_KEY</td>
        </tr>
    </tbody>
</table>