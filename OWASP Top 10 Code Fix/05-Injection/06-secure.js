///#06 Injection
/// - Secure code JavaScript


app.get('/user', (req, res) => {
    const username = req.query.username;
    if (!username || typeof username !== 'string'){
        return res.status (400).json({error: 'Invalid username parameter'});
    }
    const sanitizedUsername = username.replace(/[$.]/g, '');

    db.collection('users').findOne(
        { username: sanitizedUsername },
        { projection: { password: 0 } },
        (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Server error' });
            }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
        }
    );
});


