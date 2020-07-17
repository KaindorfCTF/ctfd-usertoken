import uuid
from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils.config import is_teams_mode
from CTFd.utils.logging import log
from flask import current_app as app
from flask import redirect, render_template, request, send_file, session, url_for
from CTFd.models import (
    Admins,
    Files,
    Notifications,
    Pages,
    Teams,
    Users,
    UserTokens,
    db,
)
from CTFd.utils import config, get_config, set_config
from CTFd.utils import validators
from CTFd.utils.helpers import get_errors, get_infos
from CTFd.utils.security.auth import login_user
from CTFd.utils.user import authed, get_current_user, is_admin
from CTFd.utils.decorators import authed_only


def register():
    errors = get_errors()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email_address = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        secret = str(uuid.uuid4())

        name_len = len(name) == 0
        names = Users.query.add_columns("name", "id").filter_by(name=name).first()
        emails = (
            Users.query.add_columns("email", "id")
                .filter_by(email=email_address)
                .first()
        )
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = validators.validate_email(email_address)
        team_name_email_check = validators.validate_email(name)

        if not valid_email:
            errors.append("Please enter a valid email address")
        if email.check_email_is_whitelisted(email_address) is False:
            errors.append(
                "Only email addresses under {domains} may register".format(
                    domains=get_config("domain_whitelist")
                )
            )
        if names:
            errors.append("That user name is already taken")
        if team_name_email_check is True:
            errors.append("Your user name cannot be an email address")
        if emails:
            errors.append("That email has already been used")
        if pass_short:
            errors.append("Pick a longer password")
        if pass_long:
            errors.append("Pick a shorter password")
        if name_len:
            errors.append("Pick a longer user name")

        if len(errors) > 0:
            return render_template(
                "register.html",
                errors=errors,
                name=request.form["name"],
                email=request.form["email"],
                password=request.form["password"],
            )
        else:
            with app.app_context():
                user = Users(name=name, email=email_address, password=password, secret=secret)
                db.session.add(user)
                db.session.commit()
                db.session.flush()

                login_user(user)

                if config.can_send_mail() and get_config(
                        "verify_emails"
                ):  # Confirming users is enabled and we can send email.
                    log(
                        "registrations",
                        format="[{date}] {ip} - {name} registered (UNCONFIRMED) with {email}",
                    )
                    email.verify_email_address(user.email)
                    db.session.close()
                    return redirect(url_for("auth.confirm"))
                else:  # Don't care about confirming users
                    if (
                            config.can_send_mail()
                    ):  # We want to notify the user that they have registered.
                        email.successful_registration_notification(user.email)

        log("registrations", "[{date}] {ip} - {name} registered with {email}")
        db.session.close()

        if is_teams_mode():
            return redirect(url_for("teams.private"))

        return redirect(url_for("challenges.listing"))
    else:
        return render_template("register.html", errors=errors)

@authed_only
def settings():
    user = get_current_user()
    name = user.name
    email = user.email
    website = user.website
    affiliation = user.affiliation
    country = user.country
    secret = user.secret

    tokens = UserTokens.query.filter_by(user_id=user.id).all()

    prevent_name_change = get_config("prevent_name_change")
    confirm_email = get_config("verify_emails") and not user.verified
    return render_template(
        "ctfd-usertoken/usertoken_settings.html",
        name=name,
        email=email,
        website=website,
        affiliation=affiliation,
        country=country,
        tokens=tokens,
        prevent_name_change=prevent_name_change,
        confirm_email=confirm_email,
        secret=secret,
    )
