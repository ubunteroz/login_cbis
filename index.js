const axios = require('axios').default;
const axios_cookie = require('axios-cookiejar-support').default;
const bodyparser = require('body-parser');
const crypto = require('crypto');
const express = require('express');
const jsdom = require('jsdom');
const qs = require('qs');
const tough = require('tough-cookie');

const app = express();
const http = require('http').Server(app);
const base_url = 'http://fisip.upnyk.ac.id';
const encryption_key = 'l337p455w0rD';

axios_cookie(axios);

app.use(bodyparser.json());
app.use(bodyparser.urlencoded({
    extended: true
}));

function encrypt(text) {
    const key = crypto.createCipher('aes-128-cbc', encryption_key);
    let output = key.update(text, 'utf8', 'hex');
    output += key.final('hex');
    return output;
}

function decrypt(text) {
    const key = crypto.createDecipher('aes-128-cbc', encryption_key);
    let output = key.update(text, 'hex', 'utf8');
    output += key.final('utf8');
    return output;
}

app.get('/captcha', async function(req, res) {
    const cookie_jar = new tough.CookieJar();

    try {
        const captcha = await axios.get(base_url + './c.php', {
            jar: cookie_jar,
            responseType: 'arraybuffer'
        });
        let token = null;

        cookie_jar.toJSON().cookies.forEach(function(cookie) {
            if (cookie.key === 'PHPSESSID') token = encrypt(cookie.value);
        });

        res.json({
            code: 'OK',
            token: token,
            captcha: 'data:image/png;base64,' + captcha.data.toString('base64')
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            code: 'ERROR_FETCHING_SESSION',
            message: 'An error occured while fetching session data from CBIS.'
        });
    }
});

app.post('/login', async function(req, res) {
    const {
        username,
        password,
        captcha,
        token
    } = req.body;

    try {
        const cookie_jar = new tough.CookieJar();
        cookie_jar.setCookieSync('PHPSESSID=' + decrypt(token), base_url);

        const login = await axios.post(base_url + '/login.html', qs.stringify({
            user_id: username,
            pwd0: password,
            fcaptcha: captcha,
            submit1: 'Login'
        }), {
            jar: cookie_jar,
            withCredentials: true
        });

        if (!login.data.includes('/menusdm.html')) {
            res.status(403).json({
                code: 'ERROR_LOGIN_FAILED',
                message: 'Login failed. Please check username, password, token, and/or captcha.'
            });
            return;
        }

        let data = {
            npm: username
        };
        let session_path;
        cookie_jar.toJSON().cookies.forEach(function(cookie) {
            switch (cookie.key) {
                case 'sessiondir':
                    session_path = cookie.path;
                    break;
                case 'namauserck':
                    data.nama = cookie.value.replace(/\+/g, ' ');
                    break;
                default:
                    // NOTE: Nope
            }
        });

        await axios.get(base_url + session_path + 'menusdm.html', {
            jar: cookie_jar,
            withCredentials: true
        });
        cookie_jar.toJSON().cookies.forEach(function(cookie) {
            if (cookie.key === 'nama_areack') data.prodi = cookie.value.replace(/\+/g, ' ');
        });

        const biodata = await axios.get(base_url + session_path + 'editbiodatamhs.html', {
            jar: cookie_jar,
            withCredentials: true
        });
        const biodata_dom = new jsdom.JSDOM(biodata.data);
        const _input_telepon = biodata_dom.window.document.querySelector('input[name="telpon2"]');
        data.telepon = _input_telepon ? _input_telepon.value : '081xxx';

        res.json({
            code: 'OK',
            ...data
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            code: 'ERROR_LOGIN',
            message: 'An error occured while processing login credential.'
        });
    }
});

app.all('*', function(req, res) {
    res.status(404).json({
        code: 'ERROR_NOT_FOUND',
        message: 'Not found.'
    });
});

app.use(function(err, req, res) {
    if (err) {
        console.error(err);
        res.status(500).json({
            code: 'ERROR_SOMETHING_BAD_HAPPENED',
            message: 'Something bad happened.'
        });
    } else {
        res.status(501).json({
            code: 'ERROR_UNHANDLED_REQUEST',
            message: 'Unhandled request.'
        });
    }
});

http.listen(8080, '0.0.0.0', function() {
    console.log('HTTP server started...');
});