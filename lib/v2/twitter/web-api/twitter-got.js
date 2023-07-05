const queryString = require('query-string');
const got = require('@/utils/got');
const config = require('@/config').value;
// https://github.com/mikf/gallery-dl/blob/a53cfc845e12d9e98fefd07e43ebffaec488c18f/gallery_dl/extractor/twitter.py#L716-L726
const headers = {
    authorization: config.twitter.authorization,
    // Bearer AAAAAAAAAAAAAAAAAAAAAPYXBAAAAAAACLXUNDekMxqa8h%2F40K4moUkGsoc%3DTYfbDKbT3jJPCEVnMYqilB28NHfOPqkca3qaAxGfsyKCs0wRbw
    // reference: https://github.com/dangeredwolf/FixTweet/blob/f3082bbb0d69798687481a605f6760b2eb7558e0/src/constants.ts#L23-L25
    // 'x-guest-token': undefined,
    'x-twitter-auth-type': 'OAuth2Session',
    'x-twitter-client-language': 'en',
    'x-twitter-active-user': 'yes',
    'x-csrf-token': config.twitter.csrfToken,
    'cookie': config.twitter.cookie,
    // Referer: 'https://twitter.com/',
};

let cookieJar;

async function twitterGot(options) {
    const response = await got({
        ...options,
        headers: { ...headers, ...(options.headers || {}) },
        cookieJar,
    });
    return response;
}

async function twitterRequest(url, params, method) {
    // 发起请求
    const request = () =>
        twitterGot({
            url,
            method,
            searchParams: queryString.stringify(params),
        });
    let response = await request();
    return response.data;
}

module.exports = twitterRequest;
