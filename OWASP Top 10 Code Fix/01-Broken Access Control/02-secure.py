""" 02 Broken Access Control
- secure code python """

from flask_login import login_required, current_user
from flask import abort

@app.route('/account/<user_id')
@login_required
def get_account(user_id):
    if current_user.role != 'admin' and str(current_user.id) != user_id:
        abort(403)
    user = db.query(User).filter_by(id=user_id).first_or_404()
    return jsonify(user.to_dict())

