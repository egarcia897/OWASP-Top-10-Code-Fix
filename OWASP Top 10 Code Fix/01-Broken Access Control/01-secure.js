/// #1 Broken Access Control
/// Secure Code Javascript

function requireAuth(req, res, next) {
    if (!req.user) return res.status(401).send('Not authenticated');
    next();
}

app.get('/profile/:userid'), requireAuth, (req, res)=> {
    const requestedId = req.params.userId;
    if (req.user.role !== 'admin' && req.user.id !== requestedId) {
        return res.status(403).send('Forbidden');
    }
    User.findById(requestedId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
