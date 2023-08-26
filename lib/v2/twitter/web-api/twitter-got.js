const queryString = require('query-string');
const got = require('@/utils/got');
const config = require('@/config').value;

// https://github.com/mikf/gallery-dl/blob/a53cfc845e12d9e98fefd07e43ebffaec488c18f/gallery_dl/extractor/twitter.py#L716-L726
const headers = {
    authorization: config.twitter.authorization,
    'x-twitter-auth-type': 'OAuth2Session',
    'x-twitter-client-language': 'en',
    'x-twitter-active-user': 'yes',
    'x-csrf-token': config.twitter.csrfToken,
    cookie: config.twitter.cookie,
};

async function twitterGot(options) {
    const response = await got({
        ...options,
        headers: { ...headers, ...(options.headers || {}) },
    });
    return response;
}

async function twitterRequest(url, params, method) {
    const request = () =>
        twitterGot({
            url,
            method,
            searchParams: queryString.stringify(params),
        });
    const response = await request();
    if (response.data.errors) {
        throw Error('API reports error:\n' + response.data.errors.map((e) => `${e.code}: ${e.message}`).join('\n'));
    }
    return response.data;
}

module.exports = twitterRequest;
