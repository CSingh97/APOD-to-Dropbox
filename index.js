const fs = require("fs");
const url = require("url");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const querystring = require("querystring");

const authorizations = require("./auth/credentials.json");
const { client_id, client_secret, scope } = authorizations.authorizations[0];
const { api_key } = authorizations.authorizations[1];

// dates where an APOD was not uploaded in the range of dates
const illegal_dates = ["date=1995-06-17", "date=1995-06-18", "date=1995-06-19", "date=1995-06-20"];

const port = 3000;

const all_sessions = [];
const server = http.createServer();

server.on("listening", listen_handler);
server.listen(port);
function listen_handler() {
    console.log(`Port open: ${port}`);
}

server.on("request", request_handler);
function request_handler(req, res) {
    console.log(`Request from ${req.socket.remoteAddress} for ${req.url}`);

    if (req.url === "/") {
        const form = fs.createReadStream("html/index.html");
        res.writeHead(200, { "Content-Type": "text/html" });
        form.pipe(res);
    }

    // url user is taken to when they request a date
    else if (req.url.startsWith("/date_search")) {
        let user_input = (req.url).substring(13);
        // check that the date entered is valid
        if (isNaN(Date.parse(user_input.substring(5))) || illegal_dates.includes(user_input) || new Date(user_input.substring(5)) > new Date())
            invalid_date(res);

        // save the date for after user is signed into dropbox
        const date = user_input;
        const state = crypto.randomBytes(20).toString("hex");
        all_sessions.push({ date, state });

        process.stdout.write("Redirecting user to Dropbox...");
        user_redirect_dropbox(state, res);
    }

    // url user is redirected to after being signed into dropbox
    else if (req.url.startsWith("/receive_code")) {
        const { code, state } = url.parse(req.url, true).query;
        let session = all_sessions.find(session => session.state === state);

        if (code === undefined || state === undefined || session === undefined)
            not_found(res);

        const date = session.date;
        get_APOD(code, date, res);
    }

    else
        not_found(res);
}

function not_found(res) {
    res.writeHead(404, { "Content-Type": "text/html" });
    res.end(`<h1>404: Something went wrong. Please try again.</h1>`);
}

function invalid_date(res) {
    res.writeHead(404, { "Content-Type": "text/html" });
    res.end(`<h1>404: Invalid date! Please go back and enter a valid date!</h1>`);
}

// function that uses the Dropbox API to sign the user in and authorize usage of their account
function user_redirect_dropbox(state, res) {
    const authorization_endpoint = "https://www.dropbox.com/oauth2/authorize";
    const response_type = "code";
    const redirect_uri = "http://localhost:3000/receive_code";
    let uri = querystring.stringify({ client_id, scope, state, response_type, redirect_uri });

    res.writeHead(302, { Location: `${authorization_endpoint}?${uri}` })
        .end();
    console.log("done!");
}

function process_stream(stream, callback, ...args) {
    stream.on("error", (err) => {
        console.log(err);
        not_found(res);
    });
    
    let body = "";
    stream.on("data", chunk => body += chunk);
    stream.on("end", () => callback(body, ...args));
}

// function to obtain the APOD from the date the user requested
function get_APOD(code, date, res) {
    process.stdout.write("Accessing and caching image from NASA APOD API...");
    // converts entered date into a date the API accepts
    date = (JSON.stringify(date)).replace(/['"]+/g, '');

    // checks that the request isn't a duplicate
    if (fs.existsSync(`./images/${date.substring(5)}.jpg`)) {
        console.log("an image matching the date is already cached, no need to access a new one!");
        send_dropbox_access_token_request(code, date.substring(5), res)
    }

    // gets the APOD
    else {
        const APOD_endpoint = `https://api.nasa.gov/planetary/apod?api_key=${api_key}&${date}`;

        https.get(APOD_endpoint,
            (APOD_stream) => process_stream(APOD_stream, save_APOD, code, res)
        ).end();
    }
}

// function that saves the obtained APOD to send to the user's Dropbox
function save_APOD(body, code, res) {
    // parse the JSON file that is returned from the APOD API request
    const APOD_JSON = JSON.parse(body);
    const APOD_path = APOD_JSON.url;
    
    // fetch the image returned
    var APOD_cache = fs.createWriteStream(`./images/${APOD_JSON.date}.jpg`);

    // pipe the image to cache
    let APOD_req = https.get(APOD_path, function (APOD_res) {
        APOD_res.pipe(APOD_cache);
        APOD_cache.on('finish', function () {
            console.log("done!");
            send_dropbox_access_token_request(code, APOD_JSON.date, res);
        });
    });
    APOD_req.on('error', function (err) { console.log(err) });
}

// function that sends a request for a token to the user's Dropbox account
function send_dropbox_access_token_request(code, date, res) {
    process.stdout.write("Getting access token from Dropbox API...");

    // checks that a new request token is in fact needed
    if (fs.existsSync('./auth/authentication-res.json')) {
        cached_auth = require('./auth/authentication-res.json');
        if (new Date(cached_auth.expiration) > new Date()) {
            console.log("a valid access token is already cached, no need to access a new one!");
            let dropbox_access_token = cached_auth;
            store_APOD_to_dropbox(dropbox_access_token, date, res);
        }
    }

    // obtains a token
    const token_endpoint = "https://api.dropboxapi.com/oauth2/token",
        grant_type = "authorization_code",
        redirect_uri = "http://localhost:3000/receive_code",
        post_data = querystring.stringify({ code, client_id, client_secret, grant_type, redirect_uri }),
        token_request_time = new Date();

    let options = {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    }

    https.request(token_endpoint,
        options,
        (token_stream) => process_stream(token_stream, receive_dropbox_access_token, token_request_time, date, res)
    ).end(post_data);
}

// function that parses the return from the token request
function receive_dropbox_access_token(body, token_request_time, date, res) {
    // parse the JSON that is returned
    const dropbox_access_token = JSON.parse(body);

    // save the expiration date
    dropbox_access_token.expiration = new Date(token_request_time.getTime() + (dropbox_access_token.expires_in * 1000));
    process.stdout.write("access token recieved, caching token...");

    // write the authentication file
    fs.writeFile("./auth/authentication-res.json", JSON.stringify(dropbox_access_token, null, 2), () => { });
    console.log("...done!");
    store_APOD_to_dropbox(dropbox_access_token, date, res)
}

// function to store the APOD image to the user's dropbox
function store_APOD_to_dropbox(dropbox_access_token, date, res) {
    process.stdout.write("Storing image to the users Dropbox...");
    // setup the parameters for the request including endpoint to upload the file, the file name which is the date requested, and the image itself
    const upload_endpoint = "https://content.dropboxapi.com/2/files/upload";
    date = (JSON.stringify(date)).replace(/['"]+/g, '');
    const file = fs.readFileSync("./images/" + date + ".jpg", {});

    // setup the variable that stores the request parameters 
    const options = {
        method: "POST",
        headers: {
            Authorization: `Bearer ${dropbox_access_token.access_token}`,
            'Dropbox-API-Arg': JSON.stringify({
                "path": `/${date}.jpg`,
                "mode": "overwrite",
            }),
            "Content-Type": "application/octet-stream"
        }
    }

    // send the request to the Dropbox API
    https.request(upload_endpoint,
        options,
        (upload_stream) => process_stream(upload_stream, receive_upload_response, file, res)
    ).end(file);

    // parse the return
    function receive_upload_response(body, file, res) {
        const upload_JSON = JSON.parse(body);
        var file_data = new Buffer.from(file).toString('base64');
        console.log(`done! Check /apps/NASA+DB${upload_JSON.path_lower}`);

        res.writeHead(200, { 'content-type': 'text/html' });
        res.write(`Done! Check your Dropbox in /apps/NASA+DB${upload_JSON.path_lower} for the image! Here's what it looks like:<br/><br/><img src='data:./images/${date.replace(/['"]+/g, '')}.jpg;base64,${file_data}'/>`)
    }
}
