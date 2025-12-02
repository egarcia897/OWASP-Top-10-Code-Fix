"""#07 Insecure Design
- Secure Code Python"""

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form['token']
    new_password = request.form['new_password']

    token_record = PasswordResetToken.query.filter_by(
        token_hash=hash(token)
    ).first_or_404()

    if token_record.is_expired() or token_record.used:
        abort(400)

    user = token_record.user
    user.password = hash_password(new_password)
    token_record.used = True
    db.session.commit()

    return 'Password reset'