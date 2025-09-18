# Orion Override

## Background
Orion Control is a web interface simulating the admin dashboard for NASA's Orion spacecraft missions. It displays mission telemetry, comms logs, and access to "abort override" functions. Players discover a login portal at /login where they can access a user dashboard. The goal is to gain unauthorized access to the admin dashboard to abort a critical mission situation.

## Objective
Exploit an HTTP parameter pollution (HPP) vulnerability to bypass login and access the admin panel to abort the mission.

## Vulnerability Details
The application has two key components that create the vulnerability:

1. Session-based authentication:
```javascript
if (req.session.isAuthenticated) {
    if (adminParam === "true" && req.session.isAdmin) {
        return res.sendFile(__dirname + '/views/admin.html');
    }
}
```

2. Query parameter handling:
```javascript
if (Array.isArray(adminParam)) {
    // multiple admin params → check only last, no session check
    if (adminParam.at(-1) === "true") {
        return res.sendFile(__dirname + '/views/admin.html');
    }
}
```

The vulnerability exists because:
- When multiple `admin` parameters are present, it only checks the last value
- The session check is bypassed when multiple parameters are present
- This allows the following exploit:
```
GET /dashboard?admin=false&admin=true
```

## Player Flow
1. Find /login page
2. Attempt login with any credentials (stored in creds.txt)
3. Notice you only have access to the user dashboard
4. Observe the critical mission situation in the comms logs
5. Notice the need for admin access to abort the mission
6. Discover the parameter handling behavior
7. Exploit the HPP vulnerability to access the admin dashboard
8. Use the abort function to get the flag

## Difficulty
Easy – requires understanding of:
- HTTP parameter pollution
- Session management
- Query parameter handling in Express.js
- How different servers parse duplicate query parameters

## Hints
- The application uses Express.js's simple query parser
- Multiple parameters with the same name are handled differently than single parameters
- The admin dashboard contains critical mission control functions
- The flag is revealed when aborting the mission

## Deployment Notes
- Ensure the challenge behaves differently based on order of params
- The application requires:
  - Node.js
  - Express.js
  - express-session
  - cookie-parser
- Credentials are stored in creds.txt in the format `username:password`
- The admin account must be present in creds.txt

## Flag
The flag is revealed when using the abort function in the admin dashboard:
`flag{httppollution_orion_<rand>}`
----