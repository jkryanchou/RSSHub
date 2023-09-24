const queryString = require('query-string');
const got = require('@/utils/got');
const config = require('@/config').value;
const logger = require('@/utils/logger');
const utils = require('../utils');

function randomChooseAccount(obj, excludes = []) {
    const keys = Object.keys(obj).filter((key) => !excludes.includes(key));
    if (keys.length === 0) {
        return null; // 如果所有的键都在排除列表中，则返回null
    }
    const randomKey = keys[Math.floor(Math.random() * keys.length)]; // 随机选择一个键
    return obj[randomKey]; // 返回对象对应这个键的值
}

const credentials = utils.loadCredentials(config.twitter.credentialsJSON);
logger.info(`Loaded ${Object.keys(credentials).length} credentials`);
logger.info(`credentials: ${JSON.stringify(credentials)}`);
const randomAccount = randomChooseAccount(credentials, []);

// https://github.com/mikf/gallery-dl/blob/a53cfc845e12d9e98fefd07e43ebffaec488c18f/gallery_dl/extractor/twitter.py#L716-L726

const headers = {
    authorization: randomAccount.authorization,
    'x-twitter-auth-type': 'OAuth2Session',
    'x-twitter-client-language': 'en',
    'x-twitter-active-user': 'yes',
    'x-csrf-token': randomAccount.csrfToken,
    cookie: randomAccount.cookie,
};

async function twitterGot(options) {
    const response = await got({
        ...options,
        headers: { ...headers, ...(options.headers || {}) },
    });
    return response;
}

function resetNextCredential(requestCookie) {
    const current = getCookieValue(requestCookie, 'twid').replace('u%3D', '');
    const next = randomChooseAccount(credentials, [current]);
    logger.info(`Switching to ${next.username}`);
    headers.authorization = next.authorization;
    headers['x-csrf-token'] = next.csrfToken;
    headers.cookie = next.cookie;
}

function getCookieValue(cookie, fieldName) {
    const fields = cookie.split(';');

    for (let i = 0; i < fields.length; i++) {
        const field = fields[i].trim();
        const parts = field.split('=');

        // 如果是我们需要的字段，返回其值
        if (parts[0] === fieldName) {
            return parts[1];
        }
    }
    return null;
}

async function twitterRequest(url, params, method) {
    resetNextCredential(headers.cookie);
    const request = () =>
        twitterGot({
            url,
            method,
            searchParams: queryString.stringify(params),
        });

    let response;
    try {
        response = await request();
        const requestRemaining = parseInt(response.headers['x-rate-limit-remaining'], 10);
        if (requestRemaining <= 5) {
            resetNextCredential(response.request.options.headers.cookie);
        }
    } catch (e) {
        if (e.response.status === 429 || (e.response.status === 404 && !e.response.data)) {
            resetNextCredential(e.response.request.options.headers.cookie);
            response = await request();
            logger.error(`429 in ${url}`);
        } else {
            logger.error(`Error in ${url}: ${e.message}`);
            throw e;
        }
    }

    if (response.data.errors) {
        throw Error('API reports error:\n' + response.data.errors.map((e) => `${e.code}: ${e.message}`).join('\n'));
    }

    // updateCredential(response);
    return response.data;
}

module.exports = twitterRequest;
