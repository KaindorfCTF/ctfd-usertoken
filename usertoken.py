import uuid
import base64

import requests
from flask import Blueprint
from flask import current_app as app
from flask import redirect, render_template, request, session, url_for
from itsdangerous.exc import BadSignature, BadTimeSignature, SignatureExpired

from CTFd.models import (
    Users,
    UserTokens,
    db,
)

from CTFd.cache import clear_team_session, clear_user_session
from CTFd.models import Teams, UserFieldEntries, UserFields, Users, db
from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils import user as current_user
from CTFd.utils import validators
from CTFd.utils.config import is_teams_mode
from CTFd.utils.config.integrations import mlc_registration
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.crypto import verify_password
from CTFd.utils.decorators import ratelimit
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.helpers import error_for, get_errors, markup
from CTFd.utils.logging import log
from CTFd.utils.modes import TEAMS_MODE
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.security.signing import unserialize
from CTFd.utils.validators import ValidationError
from CTFd.utils.decorators import authed_only

@check_registration_visibility
@ratelimit(method="POST", limit=10, interval=5)
def register():
    errors = get_errors()
    if current_user.authed():
        return redirect(url_for("challenges.listing"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email_address = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        secret = str(uuid.uuid4())

        website = request.form.get("website")
        affiliation = request.form.get("affiliation")
        country = request.form.get("country")

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

        # Process additional user fields
        fields = {}
        for field in UserFields.query.all():
            fields[field.id] = field

        entries = {}
        for field_id, field in fields.items():
            value = request.form.get(f"fields[{field_id}]", "").strip()
            if field.required is True and (value is None or value == ""):
                errors.append("Please provide all required fields")
                break

            # Handle special casing of existing profile fields
            if field.name.lower() == "affiliation":
                affiliation = value
                break
            elif field.name.lower() == "website":
                website = value
                break

            if field.field_type == "boolean":
                entries[field_id] = bool(value)
            else:
                entries[field_id] = value

        if country:
            try:
                validators.validate_country_code(country)
                valid_country = True
            except ValidationError:
                valid_country = False
        else:
            valid_country = True

        if website:
            valid_website = validators.validate_url(website)
        else:
            valid_website = True

        if affiliation:
            valid_affiliation = len(affiliation) < 128
        else:
            valid_affiliation = True

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
        if valid_website is False:
            errors.append("Websites must be a proper URL starting with http or https")
        if valid_country is False:
            errors.append("Invalid country")
        if valid_affiliation is False:
            errors.append("Please provide a shorter affiliation")

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

                if website:
                    user.website = website
                if affiliation:
                    user.affiliation = affiliation
                if country:
                    user.country = country

                db.session.add(user)
                db.session.commit()
                db.session.flush()

                for field_id, value in entries.items():
                    entry = UserFieldEntries(
                        field_id=field_id, value=value, user_id=user.id
                    )
                    db.session.add(entry)
                db.session.commit()

                login_user(user)

                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return redirect(request.args.get("next"))

                if config.can_send_mail() and get_config(
                    "verify_emails"
                ):  # Confirming users is enabled and we can send email.
                    log(
                        "registrations",
                        format="[{date}] {ip} - {name} registered (UNCONFIRMED) with {email}",
                        name=user.name,
                        email=user.email,
                    )
                    email.verify_email_address(user.email)
                    db.session.close()
                    return redirect(url_for("auth.confirm"))
                else:  # Don't care about confirming users
                    if (
                        config.can_send_mail()
                    ):  # We want to notify the user that they have registered.
                        email.successful_registration_notification(user.email)

        log(
            "registrations",
            format="[{date}] {ip} - {name} registered with {email}",
            name=user.name,
            email=user.email,
        )
        db.session.close()

        if is_teams_mode():
            return redirect(url_for("teams.private"))

        return redirect(url_for("challenges.listing"))
    else:
        return render_template("register.html", errors=errors)

@authed_only
def settings():
    infos = get_infos()

    user = get_current_user()
    name = user.name
    email = user.email
    website = user.website
    affiliation = user.affiliation
    country = user.country
    secret = user.secret

    tokens = UserTokens.query.filter_by(user_id=user.id).all()

    prevent_name_change = get_config("prevent_name_change")

    if get_config("verify_emails") and not user.verified:
        confirm_url = markup(url_for("auth.confirm"))
        infos.append(
            markup(
                "Your email address isn't confirmed!<br>"
                "Please check your email to confirm your email address.<br><br>"
                f'To have the confirmation email resent please <a href="{confirm_url}">click here</a>.'
            )
        )

    return render_template(
        "ctfd-usertoken/usertoken_settings.html",
        name=name,
        email=email,
        website=website,
        affiliation=affiliation,
        country=country,
        tokens=tokens,
        prevent_name_change=prevent_name_change,
        infos=infos,
        secret=secret,
    )