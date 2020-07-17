from .usertoken import (
    register,
    settings,
)

from flask import Blueprint

from flask import abort, request

from CTFd.models import (
    Awards,
    Notifications,
    Solves,
    Submissions,
    Tracking,
    Unlocks,
    Users,
    db,
)
from CTFd.schemas.users import UserSchema
from CTFd.utils.decorators import admins_only, authed_only, ratelimit
from CTFd.utils.decorators.visibility import (
    check_account_visibility,
    check_score_visibility,
)
from CTFd.utils.user import get_current_user, get_current_user_type, is_admin

def load(app):
    blueprint = Blueprint("usertoken", __name__, template_folder="templates")

    @blueprint.route("/api/v1/users/verify/<secret>")
    @admins_only
    @check_account_visibility
    def verify(secret):
        user = Users.query.filter_by(secret=secret).first_or_404()

        if (user.banned or user.hidden) and is_admin() is False:
            abort(404)

        user_type = get_current_user_type(fallback="user")
        response = UserSchema(view=user_type).dump(user)

        if response.errors:
            return {"success": False, "errors": response.errors}, 400

        return {"success": True}

    app.register_blueprint(blueprint)
    app.view_functions["auth.register"] = register
    app.view_functions["views.settings"] = settings
