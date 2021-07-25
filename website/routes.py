from website import app
from flask import render_template, redirect, url_for, flash, request, jsonify
from website.models import User
from website.forms import RegisterForm, LoginForm, OauthForm
from website import db
from flask_login import login_user, logout_user, login_required, current_user
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth
from werkzeug.security import gen_salt
import time


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@app.route("/")
def homepage():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(
            username=form.username.data,
            email_address=form.email_address.data,
            password=form.password1.data,
        )

        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(
            f"Account created successfully! {user_to_create.username}",
            category="success",
        )
        return redirect(url_for("homepage"))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(
                f"There was an error with creating a user: {err_msg}", category="danger"
            )

    return render_template("register.html", form=form)


@app.route("/createclient", methods=["GET", "POST"])
@login_required
def create_client():
    form = OauthForm()
    if form.validate_on_submit():
        client_id = gen_salt(24)
        client_id_issued_at = int(time.time())

        client = OAuth2Client(
            client_id=client_id,
            client_id_issued_at=client_id_issued_at,
            user_id=current_user.id,
        )
        client_metadata = {
            "client_name": form.client_name.data,
            "grant_types": split_by_crlf(form.grant_types.data),
            "response_types": split_by_crlf(form.response_types.data),
            "scope": form.scope.data,
            "token_endpoint_auth_method": "client_secret_basic",
        }
        client.client_secret = gen_salt(48)
        client.set_client_metadata(client_metadata)
        db.session.add(client)
        db.session.commit()
        flash(
            "Oaut Client Created Successfully",
            category="info",
        )
        clients = OAuth2Client.query.filter_by(user_id=current_user.id).all()
        for client in clients:
            print(client.client_info)
            print(client.client_metadata)

        return render_template("clientdata.html", user=current_user.id, clients=clients)
    return render_template("createclient.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password(
            attempted_password=form.password.data
        ):
            login_user(attempted_user)
            return redirect(url_for("homepage"))
        else:
            flash(
                "Invalid Credentials",
                category="danger",
            )

    return render_template("login.html", form=form)


@app.route("/logout")
def logoutpage():
    logout_user()
    flash("You have been logged out!", category="info")
    return redirect(url_for("homepage"))


@app.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    user = current_user.id
    if not user:
        flash("Please Login !", category="info")
        return redirect(url_for("loginpage"))
    if request.method == "GET":
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template("authorize.html", user=user, grant=grant)
    if not user and "username" in request.form:
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()
    if request.form["confirm"]:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@app.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


@app.route("/api/me")
@require_oauth("profile")
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)
