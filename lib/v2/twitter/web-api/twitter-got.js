const { CookieJar, Cookie } = require('tough-cookie');
const { promisify } = require('util');
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
    'x-csrf-token': '1f8b46a73fdd22708ec064ce621c2c49f649eac35663ebfc5ca6ba7e59e1ac70d3e073c8707781b96d0dab2892c7d61a5dc3feb2526bd2570258aec6d5f6430fb686e3de9b6c460e8b2bf763d52422f2',
    'cookie': 'guest_id_marketing=v1%3A168827829556073230; guest_id_ads=v1%3A168827829556073230; guest_id=v1%3A168827829556073230; gt=1675386719489888257; _ga=GA1.2.106607611.1688278298; _gid=GA1.2.2006452106.1688278298; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCLF0OhWJAToMY3NyZl9p%250AZCIlNjlmMjBkOGY0ZDA3ZDk3YjlhMTU1NjYxMWQ2OGU3MDY6B2lkIiUyNjJj%250AZjlkOTEyZjJhOWZjYjVmMWIyZTZlZWU3MzVjZQ%253D%253D--439f8dcf5c342d5a63ec8b403a9cacd615aaf8f8; kdt=REJzaQNgUvv2x8Ye8WkOFeUrSCy0tp0lzgbLJuHo; auth_token=1683dde7a145e2ff9b591032aa3d1a224be0222b; ct0=1f8b46a73fdd22708ec064ce621c2c49f649eac35663ebfc5ca6ba7e59e1ac70d3e073c8707781b96d0dab2892c7d61a5dc3feb2526bd2570258aec6d5f6430fb686e3de9b6c460e8b2bf763d52422f2; lang=en; twid=u%3D1669831445265920000; att=1-c8ZiUjrKC7gQpIPmCwAIZJFcdqxemrYJkJBhBgfd; personalization_id="v1_KBrSE+KevPv69tLpoij07w=="',
    // Referer: 'https://twitter.com/',
};
let cookieJar, setCookie, getCookies;

const cookiedomain = 'twitter.com';
const cookieurl = 'https://twitter.com';

async function twitterGot(options) {
    const response = await got({
        ...options,
        headers: { ...headers, ...(options.headers || {}) },
        cookieJar,
    });
    // 更新csrfToken
    
    // for (const c of await getCookies(cookieurl)) {
    //     if (c.key === 'ct0') {
    //         headers['x-csrf-token'] = c.value;
    //     }
    // }

    return response;
}

async function resetSession() {
    cookieJar = new CookieJar();
    getCookies = promisify(cookieJar.getCookies.bind(cookieJar));
    setCookie = promisify(cookieJar.setCookie.bind(cookieJar));

    // 生成csrf-token
    // const csrfToken = [...Array(16 * 2)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
    await setCookie(new Cookie({ key: 'ct0', value: csrfToken, domain: cookiedomain, secure: false }), cookieurl);
    headers['x-csrf-token'] = '1f8b46a73fdd22708ec064ce621c2c49f649eac35663ebfc5ca6ba7e59e1ac70d3e073c8707781b96d0dab2892c7d61a5dc3feb2526bd2570258aec6d5f6430fb686e3de9b6c460e8b2bf763d52422f2';
    // 发起初始化请求
    const response = await twitterGot({
        url: 'https://api.twitter.com/1.1/guest/activate.json',
        method: 'POST',
    });

    // 获取guest-token
    // TODO: OAuth2Session, 参见 https://github.com/DIYgod/RSSHub/pull/7739#discussionR655932602
    const guestToken = response.data.guest_token;
    // headers['x-guest-token'] = guestToken;
    await setCookie(new Cookie({ key: 'gt', value: guestToken, domain: cookiedomain, secure: false }), cookieurl);
    // 发起第二个初始化请求, 获取_twitter_sess

    await twitterGot({
        url: 'https://twitter.com/i/js_inst',
        method: 'GET',
        searchParams: queryString.stringify({ c_name: 'ui_metrics' }),
    });

    return cookieJar;
}

const initSession = () => cookieJar || resetSession();

async function twitterRequest(url, params, method) {
    await initSession();
    // 发起请求
    const request = () =>
        twitterGot({
            url,
            method,
            searchParams: queryString.stringify(params),
        });
    let response;
    try {
        response = await request();
    } catch (e) {
        if (e.response.status === 403) {
            await resetSession();
            response = await request();
        } else {
            throw e;
        }
    }
    return response.data;
}

module.exports = twitterRequest;
