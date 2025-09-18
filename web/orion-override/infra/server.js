const express = require('express');
const fs = require('fs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const app = express();
const port = 3000;

// Read flag from file and inject into admin.html
let adminHtmlContent = '';
try {
    const flag = fs.readFileSync('flag.txt', 'utf8').trim();
    const adminHtmlTemplate = fs.readFileSync('views/admin.html', 'utf8');
    adminHtmlContent = adminHtmlTemplate.replace('flag{temp}', flag);
    console.log('Flag loaded and injected into admin.html');
} catch (error) {
    console.error('Error loading flag:', error.message);
    // Fallback to original content if flag.txt doesn't exist
    adminHtmlContent = fs.readFileSync('views/admin.html', 'utf8');
}

// Middleware to parse URL-encoded data
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('query parser', 'simple');

// Set up session middleware
app.use(session({
    secret: 'your_secret_key', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Serve static files from the public directory (commented out for security)
// app.use(express.static('public'));

// Function to read credentials from the file
function getCredentials() {
    const data = fs.readFileSync('creds.txt', 'utf8');
    const lines = data.trim().split('\n');
    return lines.map(line => {
        const [username, password] = line.split(':');
        return { username, password };
    });
}

// if the value is an array, it returns the last value
// if the value is not an array, it returns the value
function parseQueryParam(req, key) {
    const val = req.query[key];
    if (Array.isArray(val)) return val.at(-1);
    console.log("parsed value: ", val);
    return val;
}

// Serve the login page as the default page
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

// Route for the admin dashboard
app.get('/dashboard', (req, res) => {
    // if session, then continue; otherwise exit out
    if (!req.session.isAuthenticated) {
        console.log("zero");
        return res.send('Access Denied');
    }
    const adminParam = req.query.admin;
    if (Array.isArray(adminParam)) {
        // multiple admin params → check only last, no session check
        if (adminParam.at(-1) === "true") {
            return res.send(adminHtmlContent);
        }
    } else {
        // single admin param → require session isAdmin
        if (adminParam === "true" && req.session.isAdmin) {
            return res.send(adminHtmlContent);
        }
    }

    return res.sendFile(__dirname + '/views/user.html');
});

// Route for the login page
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

// Route to handle login form submission
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const credentials = getCredentials();

    // Check all credentials
    const isValid = credentials.some(cred => cred.username === username && cred.password === password);

    if (isValid) {
        req.session.isAuthenticated = true; // Set session value
        if (username == "admin") {
            req.session.isAdmin = true;
            return res.redirect('/dashboard?admin=true');
        }
        return res.redirect('/dashboard?admin=false');
    } else {
        // Redirect back to login page with error parameter
        return res.redirect('/login?error=invalid');
    }
});

// Route to handle logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.send('Error logging out.');
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.redirect('/'); // Redirect to login page
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
